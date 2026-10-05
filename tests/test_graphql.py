import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_core import EvidenceStore, ForgeError
import forge_artifacts
import forge_graphql
import forge_network


class GraphQLAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvidenceStore(self.root)
        self.parser = argparse.ArgumentParser()
        commands = self.parser.add_subparsers()
        for module in (forge_graphql, forge_network, forge_artifacts):
            module.register(commands)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def command(self, *argv):
        args = self.parser.parse_args(argv)
        return args.handler(args, self.store)

    def save(self, name, text):
        (self.root / name).write_bytes(text.encode('utf-8'))
        return name

    def document(self, text, suffix='.graphql'):
        result = self.command('graphql-analyze', self.save('input' + suffix, text))
        return result, result['data']['documents'][0]

    def test_operations_fragments_alias_paths_variables_and_locations(self):
        text = '''# comment with ignored syntax { $bad
query Get($id: ID!, $list: [String!]! = ["private-default"]) @skip(if: false) {
  person: user(id: $id, options: {flag: PRIVATE_ENUM, count: 72319}) {
    display: name
    ...Parts @include(if: true)
    ... on Admin { level }
    ... @skip(if: false) { visible }
  }
}
fragment Parts on User { profile { label } }
mutation Change($input: Input) { update(input: $input) { id } }
subscription Changes { changed { id } }
{ anonymous }
'''
        result, document = self.document(text)
        self.assertEqual(document['status'], 'parsed')
        operations = document['operations']
        self.assertEqual([item['kind'] for item in operations], ['query', 'mutation', 'subscription', 'query'])
        self.assertEqual([item['name'] for item in operations], ['Get', 'Change', 'Changes', None])
        self.assertEqual([(item['name'], item['type']) for item in operations[0]['variables']],
                         [('id', 'ID!'), ('list', '[String!]!')])
        fields = operations[0]['fields']
        self.assertEqual(fields[0]['alias'], 'person')
        self.assertEqual(fields[1]['path'], ['user', 'name'])
        self.assertEqual(fields[1]['response_path'], ['person', 'display'])
        self.assertEqual(fields[0]['position']['line'], 3)
        self.assertEqual(fields[0]['position']['column'], 3)
        self.assertEqual(operations[0]['spreads'][0]['name'], 'Parts')
        self.assertEqual(operations[0]['spreads'][1]['type_condition'], 'Admin')
        self.assertIsNone(operations[0]['spreads'][2]['type_condition'])
        self.assertEqual(document['fragments'][0]['fields'][1]['path'], ['profile', 'label'])
        self.assertEqual(document['undefined_fragment_names'], [])
        self.assertEqual(document['citation']['sha256'], hashlib.sha256(text.encode()).hexdigest())
        serialized = json.dumps(result)
        database = self.store.connection.execute('SELECT data FROM evidence').fetchone()[0]
        for private in ('private-default', 'PRIVATE_ENUM', '72319', 'comment with ignored syntax'):
            self.assertNotIn(private, serialized)
            self.assertNotIn(private, database)
        self.assertFalse(result['data']['schema_inferred'])
        self.assertFalse(result['data']['network_performed'])

    def test_escaped_and_block_strings_comments_never_become_selections(self):
        text = r'''query Strings($s: String = "private\"quoted\nvalue\u0041") {
  first(text: "private { falseField } # not a comment")
  second(text: """private block
# literal comment { falseBlockField }
\""" escaped terminator
""")
  # genuine comment ignoredField
  third
}'''
        result, document = self.document(text)
        self.assertEqual(document['status'], 'parsed')
        self.assertEqual([item['name'] for item in document['operations'][0]['fields']], ['first', 'second', 'third'])
        self.assertNotIn('private', json.dumps(result))
        self.assertNotIn('falseBlockField', json.dumps(result))
        self.assertNotIn('ignoredField', json.dumps(result))

    def test_js_delimited_strings_and_tagged_templates_preserve_source_positions(self):
        text = '''// gql`query Fake { ignored }`
const unrelated = "not a document";
const a = gql`query Tagged($id: ID!) {
  alias: user(id: $id) { name }
}`;
const b = "mutation Quoted { save(value: \\\"private-js\\\") }";
const c = graphql`{ anonymous }`;
const unsupported = `query Untagged { omitted }`;
'''
        result = self.command('graphql-analyze', self.save('client.js', text))['data']
        documents = result['documents']
        self.assertEqual([doc['status'] for doc in documents], ['parsed'] * 3)
        self.assertEqual([doc['operations'][0]['name'] for doc in documents], ['Tagged', 'Quoted', None])
        self.assertEqual(documents[0]['operations'][0]['fields'][0]['position']['line'], 4)
        self.assertEqual(documents[0]['operations'][0]['fields'][0]['position']['column'], 3)
        self.assertEqual(documents[0]['operations'][0]['position']['offset'], text.index('query Tagged'))
        self.assertIn('untagged_template_omitted', [item['code'] for item in result['warnings']])
        for private in ('private-js', 'ignored', 'not a document', 'Untagged'):
            self.assertNotIn(private, json.dumps(result))

    def test_js_interpolation_and_ambiguous_slashes_are_explicitly_omitted(self):
        for text, warning in (
            ('const a = gql`query Visible { first }`; const b = gql`query Hidden { ${privateValue} }`;'
             'const c = gql`query Later { later }`;', 'template_interpolation_remaining_source_omitted'),
            ('const a = gql`query Visible { first }`; const regex = /gql`query Fake { fake }`/;',
             'unsupported_js_slash_remaining_source_omitted')):
            with self.subTest(warning=warning):
                result = self.command('graphql-analyze', self.save('client.js', text))['data']
                self.assertEqual(len(result['documents']), 1)
                self.assertEqual(result['documents'][0]['operations'][0]['name'], 'Visible')
                self.assertIn(warning, [item['code'] for item in result['warnings']])
                self.assertNotIn('privateValue', json.dumps(result))
                self.assertNotIn('Hidden', json.dumps(result))
                self.assertNotIn('Fake', json.dumps(result))

    def test_json_envelope_batches_operation_name_and_persisted_absent_query(self):
        digest = 'a' * 64
        value = [{'query': 'query One($x: Int = 77881) { field(value: "private-envelope") }',
                  'operationName': 'One', 'variables': {'x': 93812}},
                 {'operationName': 'Missing', 'extensions': {'persistedQuery': {'version': 1, 'sha256Hash': digest}}}]
        result = self.command('graphql-analyze', self.save('request.json', json.dumps(value)))['data']
        first, absent = result['documents']
        self.assertTrue(first['operation_name_matches'])
        self.assertEqual(first['citation']['batch_index'], 0)
        self.assertEqual(absent['status'], 'document_absent')
        self.assertFalse(absent['document_available'])
        self.assertEqual(absent['operations'], [])
        self.assertEqual(absent['persisted_query']['sha256_hash'], digest)
        self.assertFalse(absent['persisted_query']['document_recovered'])
        serialized = self.store.connection.execute('SELECT data FROM evidence').fetchone()[0]
        for private in ('77881', '93812', 'private-envelope'):
            self.assertNotIn(private, serialized)

    def test_real_har_and_live_stored_requests_without_response_or_literal_export(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"data":{"private-response-field":"private-response-value"}}')

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/graphql'
            live = self.command('probe', self.save('live.json', json.dumps({
                'url': url, 'method': 'POST', 'json': {
                    'query': 'query Live($id: ID!) { person: user(id: $id, choice: "private-live") { id } }',
                    'operationName': 'Live', 'variables': {'id': 'private-variable'}}})))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        har = self.command('har-import', self.save('capture.har', json.dumps({'log': {'entries': [{
            'request': {'url': 'https://fixture.example/graphql?' + urlencode({
                'query': 'query Captured { me(choice: "private-har") { ...Parts } } fragment Parts on User { id }',
                'operationName': 'Captured'}), 'method': 'GET', 'headers': []},
            'response': {'status': 202, 'headers': [], 'content': {'text': '{"private-captured-response": true}'}}
        }]}})))['exchanges'][0]
        before = self.store.connection.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]
        record = self.command('graphql-analyze', '--evidence', live['id'], '--evidence', har['id'])
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], before + 1)
        documents = record['data']['documents']
        self.assertEqual([item['operations'][0]['name'] for item in documents], ['Live', 'Captured'])
        self.assertEqual([item['citation']['observation'] for item in documents], ['live_http', 'captured_http'])
        self.assertTrue(all(item['citation']['response_observed'] for item in documents))
        self.assertEqual({item['citation']['evidence_id'] for item in documents}, {live['id'], har['id']})
        self.assertEqual(documents[1]['fragments'][0]['name'], 'Parts')
        database = self.store.connection.execute('SELECT data FROM evidence WHERE id=?', (record['id'],)).fetchone()[0]
        for private in ('private-live', 'private-variable', 'private-har', 'private-response-value',
                        'private-response-field', 'private-captured-response', 'fixture.example'):
            self.assertNotIn(private, database)
        self.assertEqual(self.store.get(live['id']), live)

    def test_real_har_raw_and_form_bodies_and_hash_only_request(self):
        digest = 'b' * 64
        bodies = [
            ('application/graphql', 'mutation Raw { save(value: "private-raw-body") { id } }'),
            ('application/x-www-form-urlencoded', urlencode({
                'query': 'query Form { item(choice: "private-form-body") }', 'operationName': 'Form'})),
            ('application/json', json.dumps({'operationName': 'Persisted', 'variables': {'id': 'private-id'},
                'extensions': {'persistedQuery': {'version': 1, 'sha256Hash': digest}}})),
        ]
        entries = [{'request': {'url': 'https://fixture.example/graphql', 'method': 'POST',
                               'headers': [{'name': 'Content-Type', 'value': content_type}],
                               'postData': {'text': body}},
                    'response': {'status': 200, 'headers': [], 'content': {'text': '{}'}}}
                   for content_type, body in bodies]
        exchanges = self.command('har-import', self.save('bodies.har', json.dumps({
            'log': {'entries': entries}})))['exchanges']
        argv = ['graphql-analyze']
        for exchange in exchanges:
            argv.extend(['--evidence', exchange['id']])
        record = self.command(*argv)
        raw, form, absent = record['data']['documents']
        self.assertEqual(raw['operations'][0]['name'], 'Raw')
        self.assertEqual(form['operations'][0]['name'], 'Form')
        self.assertTrue(form['operation_name_matches'])
        self.assertEqual(absent['status'], 'document_absent')
        self.assertEqual(absent['persisted_query']['sha256_hash'], digest)
        self.assertFalse(absent['persisted_query']['document_recovered'])
        for private in ('private-raw-body', 'private-form-body', 'private-id'):
            self.assertNotIn(private, json.dumps(record))

    def test_line_terminators_and_unicode_escapes(self):
        for newline in ('\n', '\r', '\r\n'):
            with self.subTest(newline=repr(newline)):
                _, document = self.document('# comment' + newline + 'query Newline {' + newline + '  field' + newline + '}')
                self.assertEqual(document['status'], 'parsed')
                self.assertEqual(document['operations'][0]['position']['line'], 2)
                self.assertEqual(document['operations'][0]['fields'][0]['position']['line'], 3)
                self.assertEqual(document['operations'][0]['fields'][0]['position']['column'], 3)
        for value in (r'\uD83D\uDE00', r'\u{1F600}'):
            _, document = self.document('{ field(value: "' + value + '") }')
            self.assertEqual(document['status'], 'parsed')
        for value in (r'\uD800', r'\uDC00', r'\u{D800}', r'\u{110000}'):
            _, document = self.document('{ field(value: "' + value + '") }')
            self.assertEqual(document['status'], 'parse_failed')
            self.assertEqual(document['failure']['code'], 'invalid_string_escape')

    def test_invalid_json_batches_names_and_hashes_never_echo_values(self):
        record = self.command('graphql-analyze', self.save('bad.json', '{"query": "private-truncated'))['data']
        self.assertEqual(record['documents'], [])
        self.assertIn('invalid_json_envelope', [item['code'] for item in record['warnings']])
        self.assertNotIn('private-truncated', json.dumps(record))
        value = [[{'query': '{ omitted }'}], {'query': '{ visible }', 'operationName': 'private invalid name',
            'extensions': {'persistedQuery': {'sha256Hash': 'private invalid hash', 'version': 1}}}]
        result = self.command('graphql-analyze', self.save('invalid-metadata.json', json.dumps(value)))['data']
        self.assertEqual(len(result['documents']), 1)
        self.assertEqual(result['documents'][0]['status'], 'parsed')
        self.assertIsNone(result['documents'][0]['operation_name'])
        self.assertIsNone(result['documents'][0]['persisted_query']['sha256_hash'])
        codes = [item['code'] for item in result['warnings']]
        for code in ('nested_request_batch_omitted', 'invalid_operation_name_omitted', 'invalid_persisted_hash_omitted'):
            self.assertIn(code, codes)
        self.assertNotIn('private invalid', json.dumps(result))

    def test_actual_static_index_reassembles_contiguous_lines_and_search_remains_partial(self):
        source = self.save('client.graphql', 'query Indexed {\n  viewer(choice: "private-static") {\n    id\n  }\n}\n')
        index = self.command('artifact-index', source)
        search = self.command('search', 'query Indexed', source)
        (self.root / source).unlink()
        result = self.command('graphql-analyze', '--evidence', index['id'], '--evidence', search['id'])['data']
        parsed, partial = result['documents']
        self.assertEqual(parsed['status'], 'parsed')
        self.assertEqual(parsed['operations'][0]['fields'][1]['path'], ['viewer', 'id'])
        self.assertEqual(parsed['citation']['evidence_id'], index['id'])
        self.assertEqual(parsed['citation']['location']['source'], source)
        self.assertIn('index_sha256', parsed['citation'])
        self.assertEqual(partial['status'], 'parse_failed')
        self.assertEqual(partial['citation']['evidence_id'], search['id'])
        self.assertTrue(result['omissions'])
        self.assertNotIn('private-static', json.dumps(result))

    def test_static_index_recorded_identity_and_size_are_enforced(self):
        source = self.save('identity.graphql', 'query Original { field }')
        index = self.command('artifact-index', source)
        analyzed = self.command('graphql-analyze', '--evidence', index['id'])['data']['documents'][0]
        self.assertTrue(analyzed['citation']['index_recorded_identity_verified'])
        self.assertTrue(analyzed['citation']['index_recorded_size_verified'])
        wrong_size = self.store.add('analysis', {**index['data'], 'index_size': index['data']['index_size'] + 1})
        with self.assertRaisesRegex(ForgeError, 'size does not match'):
            self.command('graphql-analyze', '--evidence', wrong_size['id'])
        path = self.root / index['data']['path']
        original = path.read_bytes()
        self.assertIn(b'Original', original)
        path.write_bytes(original.replace(b'Original', b'Modified'))
        with self.assertRaisesRegex(ForgeError, 'SHA256 does not match'):
            self.command('graphql-analyze', '--evidence', index['id'])

    def test_legacy_static_index_hash_only_cites_current_observed_bytes(self):
        source = self.save('legacy.graphql', 'query Legacy { field }')
        index = self.command('artifact-index', source)
        legacy = self.store.add('analysis', {key: value for key, value in index['data'].items()
                                             if key not in {'index_sha256', 'index_size'}})
        result = self.command('graphql-analyze', '--evidence', legacy['id'])['data']
        citation = result['documents'][0]['citation']
        self.assertFalse(citation['index_recorded_identity_verified'])
        self.assertFalse(citation['index_recorded_size_verified'])
        self.assertEqual(citation['index_sha256'], hashlib.sha256(
            (self.root / index['data']['path']).read_bytes()).hexdigest())
        self.assertIn('legacy_static_index_identity_unverified', [warning['code'] for warning in result['warnings']])

    def test_invalid_truncated_and_unsupported_documents_do_not_publish_partial_operations(self):
        for text, failure in (
            ('query Good { x } query Broken {', 'invalid_structure'),
            ('query Broken { x(value: "private-unterminated)', 'unterminated_string'),
            ('query Broken { x(value: "bad\\q") }', 'invalid_string_escape'),
            ('query Broken { x(value: 01) }', 'invalid_number'),
            ('query Broken { }', 'invalid_structure'),
            ('query Broken() { x }', 'invalid_structure'),
            ('query Broken($x: Int = $other) { x }', 'invalid_structure'),
            ('type User { id: ID }', 'unsupported_definition'),
            ('# only comment', 'empty_document')):
            with self.subTest(text=text):
                _, document = self.document(text)
                self.assertEqual(document['status'], 'parse_failed')
                self.assertEqual(document['failure']['code'], failure)
                self.assertEqual(document['operations'], [])
                self.assertEqual(document['fragments'], [])
                self.assertNotIn('private-unterminated', json.dumps(document))
                self.assertIn('line', document['failure']['position'])

    def test_caps_depth_tokens_document_size_and_count(self):
        _, document = self.document('{ x ' * (forge_graphql.MAX_DEPTH + 2) + '}' * (forge_graphql.MAX_DEPTH + 2))
        self.assertEqual(document['failure']['code'], 'depth_limit')
        _, document = self.document('{ ' + 'x ' * forge_graphql.MAX_TOKENS + '}')
        self.assertEqual(document['failure']['code'], 'token_limit')
        result, document = self.document('#' + 'x' * forge_graphql.MAX_DOCUMENT_CHARACTERS)
        self.assertEqual(document['status'], 'omitted')
        self.assertIn('document_size_limit', [item['code'] for item in result['data']['warnings']])
        batch = [{'query': '{ field }'}] * (forge_graphql.MAX_DOCUMENTS + 1)
        result = self.command('graphql-analyze', self.save('batch.json', json.dumps(batch)))['data']
        self.assertEqual(len(result['documents']), forge_graphql.MAX_DOCUMENTS)
        self.assertIn('batch_document_limit', [item['code'] for item in result['warnings']])

    def test_input_selection_project_boundary_and_provenance(self):
        with self.assertRaisesRegex(ForgeError, 'explicit'):
            self.command('graphql-analyze')
        outside = self.root.parent / (self.root.name + '-outside.graphql')
        try:
            outside.write_text('{ x }', encoding='utf-8')
            with self.assertRaisesRegex(ForgeError, 'inside'):
                self.command('graphql-analyze', str(outside))
        finally:
            outside.unlink(missing_ok=True)
        unrelated = self.store.add('artifact', {'source': 'manual'})
        with self.assertRaisesRegex(ForgeError, 'must be HTTP'):
            self.command('graphql-analyze', '--evidence', unrelated['id'])
        invalid = self.store.add('http_probe', {'source': 'har_import', 'request': {}, 'response': {}})
        with self.assertRaisesRegex(ForgeError, 'provenance'):
            self.command('graphql-analyze', '--evidence', invalid['id'])
        oversized = self.save('oversized.graphql', 'x' * (forge_graphql.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(ForgeError, 'file limit'):
            self.command('graphql-analyze', oversized)


if __name__ == '__main__':
    unittest.main()
