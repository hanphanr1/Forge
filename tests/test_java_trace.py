import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge_java_trace import trace_source


MARKER_KINDS = {"url_call", "dispatch_call", "retrofit_annotation"}

DIRECT_SOURCE = """package com.example.net;

class Client {
    void send() {
        Request request = new Request.Builder()
                .url("https://api.example.test/v1/send")
                .build();
        client.newCall(request).enqueue(callback);
    }

    void refresh() {
        this.send();
        new Request.Builder().url("https://api.example.test/v1/send").build();
    }
}
"""

CALLER_SOURCE = """package com.example.net;

class Client {
    Helper helper = new Helper();

    void target() {
        String u = "https://api.example.test/v1/target";
    }

    void plainCall() {
        target();
    }

    void thisCall() {
        this.target();
    }

    void qualifiedCall() {
        Client.target();
    }

    void receiverCall() {
        helper.target();
    }
}

class Other {
    Client client = new Client();

    void call() {
        client.target();
    }
}
"""

CONSTRUCTOR_SOURCE = """package com.example.net;

class ApiClient {
    private final String baseUrl;

    ApiClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    static ApiClient create() {
        return new ApiClient("https://api.grok.test/v1/base");
    }

    String readThis() {
        return this.baseUrl;
    }

    String readQualified() {
        return ApiClient.baseUrl;
    }
}
"""

MULTI_SOURCE = """package com.example.net;

class Multi {
    private final String token;
    private final int retries;
    private final String baseUrl;
    private final boolean secure;
    private final String tag;

    Multi(String token, int retries, String baseUrl, boolean secure, String tag) {
        this.token = token;
        this.retries = retries;
        this.baseUrl = baseUrl;
        this.secure = secure;
        this.tag = tag;
    }

    static Multi create() {
        return new Multi("t", 3, "https://api.example.test/v1/multi", true, "tag");
    }

    String read() {
        return this.baseUrl;
    }
}
"""

ENTIRE_SOURCE = """package com.example.net;

class Entire {
    private final String baseUrl;

    Entire(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    static Entire concat() {
        return new Entire("prefix-" + "https://api.example.test/v1/concat");
    }

    static Entire wrapped() {
        return new Entire(helper("https://api.example.test/v1/wrapped"));
    }

    static String helper(String value) {
        return value;
    }

    String read() {
        return this.baseUrl;
    }
}
"""

AMBIGUOUS_SOURCE = """package com.example.net;

class Ambiguous {
    private final String baseUrl = null;
    private final int retries = 0;

    Ambiguous(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    Ambiguous(int retries) {
        this.retries = retries;
    }

    static Ambiguous create() {
        return new Ambiguous("https://api.example.test/v1/amb");
    }
}
"""

OVERLOAD_SOURCE = """package com.example.net;

class Overloads {
    void fetch(String url) {
        String u = "https://api.example.test/v1/fetch-text";
    }

    void fetch(int id) {
        String v = "https://api.example.test/v1/fetch-id";
    }

    void caller() {
        fetch("x");
    }
}
"""

NESTED_SOURCE = """package com.example.net;

class Outer {
    private final String baseUrl = "https://api.example.test/v1/nested-field";

    String readOuter() {
        return this.baseUrl;
    }

    class Inner {
        void target() {
            String v = "https://api.example.test/v1/inner";
        }

        void callInner() {
            target();
        }

        String readFromInner() {
            return baseUrl;
        }
    }

    void target() {
        String u = "https://api.example.test/v1/outer";
    }

    void callOuter() {
        target();
    }
}
"""

MESSY_SOURCE = r'''package com.example.net;

class Messy {
    // .url("https://api.example.test/v1/comment-only")
    // void ghost() { target(); }
    String doc = "void other() { .url(\"https://api.example.test/v1/quoted\"); }";
    char open = '{';
    char close = '}';

    void target() {
        String u = "https://api.example.test/v1/live";
        // ghost().url("https://api.example.test/v1/comment-call");
        String fake = "target(); .url(\"https://api.example.test/v1/fake\");";
    }

    void caller() {
        target();
    }
}
'''

SHADOW_SOURCE = """package com.example.net;

class Shadowed {
    private final String baseUrl = "https://api.example.test/v1/base";

    String clean() {
        return baseUrl;
    }

    String shadowedByParameter(String baseUrl) {
        return baseUrl;
    }

    String explicitThis() {
        return this.baseUrl;
    }

    String shadowedByLocal() {
        String baseUrl = other();
        return baseUrl;
    }
}
"""

ANNOTATION_SOURCE = """package com.example.net;

class Api {
    @GET("https://api.example.test/v1/annotation")
    Call list() {
        return null;
    }

    Call other() {
        return null;
    }
}
"""

KOTLIN_SOURCE = """class Api {
    fun send() {
        val u = "https://api.example.test/v1/kotlin"
    }
}
"""

SMALI_SOURCE = """.class public Lcom/example/Api;
.super Ljava/lang/Object;

.method public send()V
    .locals 1

    const-string v0, "https://api.example.test/v1/smali"

    return-void
.end method
"""

UNTERMINATED_SOURCE = """package com.example.net;

class Broken {
    void send() {
        String u = "https://api.example.test/v1/unterminated";
"""

EXTRA_BRACE_SOURCE = """package com.example.net;

class Broken {
    void ghost() {
    }
}

class Later {
    void send() {
        String u = "https://api.example.test/v1/extra-brace";
    }
}
"""


def _position(source, index):
    return (source.count("\n", 0, index) + 1, index - source.rfind("\n", 0, index))


def position_of(source, needle):
    return _position(source, source.index(needle))


def position_of_after(source, anchor, needle):
    return _position(source, source.index(needle, source.index(anchor)))


def line_of(source, needle):
    return position_of(source, needle)[0]


def line_of_after(source, anchor, needle):
    return position_of_after(source, anchor, needle)[0]


def count_items(data):
    total = 0
    for roots in data["traces"].values():
        for root in roots:
            total += 1 + len(root.get("request_markers", [])) + len(root.get("callers", []))
            for link in root.get("field_links", []):
                total += 1
                for use in link.get("uses", []):
                    total += 1 + len(use.get("request_markers", [])) + len(use.get("callers", []))
    return total


class JavaTraceTests(unittest.TestCase):
    def assert_markers_live_in_method(self, root):
        for marker in root["request_markers"]:
            self.assertIn(marker["marker_kind"], MARKER_KINDS)
            self.assertGreaterEqual(marker["line"], root["method_line"])
            self.assertLessEqual(marker["line"], root["method_end_line"])

    def assert_use_shape(self, use):
        self.assertEqual(use["resolution"], "same_class_field_candidate")
        self.assertIsInstance(use["line"], int)
        self.assertIsInstance(use["method_name"], str)
        self.assertNotIn("(", use["method_name"])

    def test_empty_literal_map_is_an_empty_summary(self):
        data = trace_source(DIRECT_SOURCE, {}, 16)
        self.assertEqual(data["traces"], {})
        self.assertEqual(data["items"], 0)
        self.assertEqual(data["omitted"], 0)
        self.assertFalse(data["truncated"])

    def test_direct_literals_map_to_enclosing_multiline_methods(self):
        source = DIRECT_SOURCE
        url = "https://api.example.test/v1/send"
        first = position_of(source, url)
        second = position_of_after(source, "this.send();", url)
        data = trace_source(source, {"send": [first, second]}, 64)

        roots = {root["method_name"]: root for root in data["traces"]["send"]}
        self.assertEqual(set(roots), {"send", "refresh"})

        sending = roots["send"]
        self.assertEqual((sending["literal_line"], sending["literal_column"]), first)
        self.assertEqual(sending["context_kind"], "method")
        self.assertEqual(sending["method_line"], line_of(source, "void send() {"))
        self.assertEqual(sending["method_end_line"], line_of(source, "    }\n\n    void refresh() {"))
        self.assertIn((first[0], "url_call"),
                      {(marker["line"], marker["marker_kind"]) for marker in sending["request_markers"]})
        # `.enqueue(` anywhere in the enclosing method is a dispatch marker, not a dataflow claim
        self.assertIn((line_of(source, ".enqueue(callback);"), "dispatch_call"),
                      {(marker["line"], marker["marker_kind"]) for marker in sending["request_markers"]})
        self.assert_markers_live_in_method(sending)

        refreshing = roots["refresh"]
        self.assertEqual((refreshing["literal_line"], refreshing["literal_column"]), second)
        self.assertEqual(refreshing["context_kind"], "method")
        self.assertEqual(refreshing["method_line"], line_of(source, "void refresh() {"))
        self.assertEqual(refreshing["method_end_line"], line_of(source, "    }\n}"))
        self.assertIn((second[0], "url_call"),
                      {(marker["line"], marker["marker_kind"]) for marker in refreshing["request_markers"]})
        self.assert_markers_live_in_method(refreshing)
        self.assertEqual(refreshing.get("callers", []), [])

    def test_method_root_carries_only_same_class_caller_candidates(self):
        source = DIRECT_SOURCE
        url = "https://api.example.test/v1/send"
        data = trace_source(source, {"send": [position_of(source, url)]}, 64)
        root = data["traces"]["send"][0]

        self.assertEqual(len(root["callers"]), 1)
        caller = root["callers"][0]
        self.assertEqual(caller["line"], line_of(source, "this.send();"))
        self.assertEqual(caller["method_name"], "refresh")
        self.assertEqual(caller["method_line"], line_of(source, "void refresh() {"))
        self.assertEqual(caller["resolution"], "same_class_name_candidate")
        self.assertEqual(caller["overload_count"], 1)

    def test_callers_exclude_receivers_other_classes_and_declarations(self):
        source = CALLER_SOURCE
        data = trace_source(source, {"target": [position_of(source, "https://api.example.test/v1/target")]}, 64)
        root = data["traces"]["target"][0]
        self.assertEqual(root["method_name"], "target")
        self.assertEqual(root["method_line"], line_of(source, "void target() {"))
        self.assertEqual(root["method_end_line"], line_of(source, "    }\n\n    void plainCall() {"))

        callers = {caller["line"]: caller for caller in root["callers"]}
        # the first bare `target();` in the file belongs to plainCall()
        self.assertEqual(set(callers), {line_of(source, "target();"),
                                        line_of(source, "this.target();"),
                                        line_of(source, "Client.target();")})
        self.assertEqual(callers[line_of(source, "target();")]["method_name"], "plainCall")
        self.assertEqual(callers[line_of(source, "this.target();")]["method_name"], "thisCall")
        self.assertEqual(callers[line_of(source, "Client.target();")]["method_name"], "qualifiedCall")
        self.assertEqual(callers[line_of(source, "target();")]["method_line"], line_of(source, "void plainCall() {"))
        self.assertEqual(callers[line_of(source, "this.target();")]["method_line"], line_of(source, "void thisCall() {"))
        self.assertEqual(callers[line_of(source, "Client.target();")]["method_line"], line_of(source, "void qualifiedCall() {"))
        # `helper.target();` and class Other's `client.target();` are receiver calls, not candidates
        self.assertNotIn(line_of(source, "helper.target();"), callers)
        self.assertNotIn(line_of(source, "client.target();"), callers)
        for caller in callers.values():
            self.assertEqual(caller["resolution"], "same_class_name_candidate")
            self.assertEqual(caller["overload_count"], 1)

    def test_constructor_literal_binds_parameter_to_field_reads(self):
        source = CONSTRUCTOR_SOURCE
        url = "https://api.grok.test/v1/base"
        literal = position_of(source, url)
        data = trace_source(source, {"base": [literal]}, 64)
        self.assertEqual(len(data["traces"]["base"]), 1)
        root = data["traces"]["base"][0]

        self.assertEqual((root["literal_line"], root["literal_column"]), literal)
        self.assertEqual(root["context_kind"], "method")
        self.assertEqual(root["method_name"], "create")
        self.assertEqual(root["method_line"], line_of(source, "static ApiClient create() {"))
        self.assertEqual(root["method_end_line"], line_of(source, "    }\n\n    String readThis() {"))
        self.assertEqual(root.get("callers", []), [])
        self.assertEqual(root.get("request_markers", []), [])

        links = root["field_links"]
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["field_name"], "baseUrl")
        self.assertEqual(link["parameter_name"], "baseUrl")
        self.assertEqual(link["argument_index"], 1)
        self.assertEqual(link["constructor_line"], line_of(source, "ApiClient(String baseUrl) {"))
        self.assertEqual(link["assignment_line"], line_of(source, "this.baseUrl = baseUrl;"))
        self.assertEqual(link["resolution"], "syntactic_constructor_binding")

        uses = {use["line"]: use for use in link["uses"]}
        self.assertEqual(set(uses), {line_of(source, "return this.baseUrl;"),
                                     line_of(source, "return ApiClient.baseUrl;")})
        self.assertEqual(uses[line_of(source, "return this.baseUrl;")]["method_name"], "readThis")
        self.assertEqual(uses[line_of(source, "return this.baseUrl;")]["method_line"],
                         line_of(source, "String readThis() {"))
        self.assertEqual(uses[line_of(source, "return ApiClient.baseUrl;")]["method_name"], "readQualified")
        self.assertEqual(uses[line_of(source, "return ApiClient.baseUrl;")]["method_line"],
                         line_of(source, "String readQualified() {"))
        for use in uses.values():
            self.assert_use_shape(use)
        # the constructor assignment is a write, never a use
        self.assertNotIn(link["assignment_line"], uses)

    def test_multi_argument_constructor_binds_the_matching_argument_index(self):
        source = MULTI_SOURCE
        url = "https://api.example.test/v1/multi"
        data = trace_source(source, {"multi": [position_of(source, url)]}, 64)
        root = data["traces"]["multi"][0]
        self.assertEqual(root["method_name"], "create")
        self.assertEqual(root["context_kind"], "method")

        links = root["field_links"]
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["argument_index"], 3)
        self.assertEqual(link["parameter_name"], "baseUrl")
        self.assertEqual(link["field_name"], "baseUrl")
        self.assertEqual(link["assignment_line"], line_of(source, "this.baseUrl = baseUrl;"))
        self.assertEqual(link["resolution"], "syntactic_constructor_binding")
        uses = [use["line"] for use in link["uses"]]
        self.assertEqual(uses, [line_of(source, "return this.baseUrl;")])
        self.assert_use_shape(link["uses"][0])

    def test_constructor_arguments_that_are_not_the_entire_literal_do_not_bind(self):
        source = ENTIRE_SOURCE
        concat = position_of(source, "https://api.example.test/v1/concat")
        wrapped = position_of(source, "https://api.example.test/v1/wrapped")
        data = trace_source(source, {"concat": [concat], "wrapped": [wrapped]}, 64)

        concat_root = data["traces"]["concat"][0]
        self.assertEqual(concat_root["context_kind"], "method")
        self.assertEqual(concat_root["method_name"], "concat")
        self.assertEqual(concat_root.get("field_links", []), [])
        self.assertIsNone(concat_root.get("field_name"))

        wrapped_root = data["traces"]["wrapped"][0]
        self.assertEqual(wrapped_root["context_kind"], "method")
        self.assertEqual(wrapped_root["method_name"], "wrapped")
        self.assertEqual(wrapped_root.get("field_links", []), [])
        self.assertIsNone(wrapped_root.get("field_name"))

    def test_overloaded_constructor_blocks_field_link(self):
        source = AMBIGUOUS_SOURCE
        data = trace_source(source, {"amb": [position_of(source, "https://api.example.test/v1/amb")]}, 64)
        root = data["traces"]["amb"][0]
        self.assertEqual(root["context_kind"], "method")
        self.assertEqual(root["method_name"], "create")
        self.assertEqual(root["method_line"], line_of(source, "static Ambiguous create() {"))
        self.assertEqual(root.get("field_links", []), [])
        self.assertIsNone(root.get("field_name"))

    def test_overload_count_stays_explicit(self):
        source = OVERLOAD_SOURCE
        text = position_of(source, "https://api.example.test/v1/fetch-text")
        ident = position_of(source, "https://api.example.test/v1/fetch-id")
        data = trace_source(source, {"text": [text], "id": [ident]}, 64)
        call_line = line_of(source, 'fetch("x");')

        first = data["traces"]["text"][0]
        self.assertEqual(first["method_name"], "fetch")
        self.assertEqual(first["method_line"], line_of(source, "void fetch(String url) {"))
        self.assertEqual(first["method_end_line"], line_of(source, "    }\n\n    void fetch(int id) {"))

        second = data["traces"]["id"][0]
        self.assertEqual(second["method_name"], "fetch")
        self.assertEqual(second["method_line"], line_of(source, "void fetch(int id) {"))
        self.assertEqual(second["method_end_line"], line_of(source, "    }\n\n    void caller() {"))

        for root in (first, second):
            self.assertEqual([(caller["line"], caller["method_name"]) for caller in root["callers"]],
                             [(call_line, "caller")])
            caller = root["callers"][0]
            self.assertEqual(caller["method_line"], line_of(source, "void caller() {"))
            self.assertEqual(caller["resolution"], "same_class_name_candidate")
            # two same-named declarations in this class: the count must not collapse to one
            self.assertEqual(caller["overload_count"], 2)

    def test_annotation_argument_literal_is_attributed_to_the_annotated_method(self):
        source = ANNOTATION_SOURCE
        literal = position_of(source, "https://api.example.test/v1/annotation")
        data = trace_source(source, {"annotation": [literal]}, 64)
        self.assertEqual(len(data["traces"]["annotation"]), 1)
        root = data["traces"]["annotation"][0]

        self.assertEqual((root["literal_line"], root["literal_column"]), literal)
        self.assertEqual(root["context_kind"], "method")
        self.assertEqual(root["method_name"], "list")
        self.assertEqual(root["method_end_line"], line_of(source, "    }\n\n    Call other() {"))
        # declaration start is either the annotation line or the signature line, never the other method
        self.assertIn(root["method_line"], (literal[0], line_of(source, "Call list() {")))
        self.assertIn((line_of(source, '@GET("https://api.example.test/v1/annotation")'), "retrofit_annotation"),
                      {(marker["line"], marker["marker_kind"]) for marker in root["request_markers"]})

    def test_nested_class_bodies_are_unsupported_and_not_absorbed_by_the_outer_class(self):
        source = NESTED_SOURCE
        outer_literal = position_of(source, "https://api.example.test/v1/outer")
        inner_literal = position_of(source, "https://api.example.test/v1/inner")
        field_literal = position_of(source, "https://api.example.test/v1/nested-field")
        data = trace_source(source, {"outer": [outer_literal],
                                     "inner": [inner_literal],
                                     "field": [field_literal]}, 64)

        # the outer method declared after the nested class still resolves: the nested body is skipped,
        # it does not swallow the rest of the outer class
        outer_root = data["traces"]["outer"][0]
        self.assertEqual(outer_root["context_kind"], "method")
        self.assertEqual(outer_root["method_name"], "target")
        self.assertEqual(outer_root["method_line"], line_of(source, "void target() {\n        String u"))
        self.assertEqual(outer_root["method_end_line"], line_of(source, "    }\n\n    void callOuter() {"))
        outer_call = line_of_after(source, "void callOuter() {", "target();")
        inner_call = line_of_after(source, "void callInner() {", "target();")
        self.assertEqual([(caller["line"], caller["method_name"]) for caller in outer_root["callers"]],
                         [(outer_call, "callOuter")])
        self.assertNotIn(inner_call, [caller["line"] for caller in outer_root["callers"]])

        # the inner literal is unsupported and never attributed to Outer's method scope
        inner_root = data["traces"]["inner"][0]
        self.assertEqual(inner_root["context_kind"], "unsupported")
        # nothing from Outer is attached to it, and nothing leaks out of the nested body
        self.assertIsNone(inner_root.get("method_name"))
        self.assertEqual(inner_root.get("field_links", []), [])
        self.assertEqual(inner_root.get("callers", []), [])
        self.assertNotEqual(inner_root["literal_line"], outer_root["method_line"])

        # the outer field's reads come from the outer class body only, never from the nested body
        field_root = data["traces"]["field"][0]
        self.assertEqual(field_root["context_kind"], "field_initializer")
        self.assertEqual(field_root["field_name"], "baseUrl")
        links = field_root["field_links"]
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["resolution"], "direct_field_initializer")
        use_lines = [use["line"] for use in link["uses"]]
        self.assertEqual(use_lines, [line_of(source, "return this.baseUrl;")])
        self.assertNotIn(line_of_after(source, "String readFromInner() {", "return baseUrl;"), use_lines)
        self.assert_use_shape(link["uses"][0])

    def test_comments_strings_and_character_braces_do_not_fake_code(self):
        source = MESSY_SOURCE
        live = position_of(source, "https://api.example.test/v1/live")
        data = trace_source(source, {"live": [live]}, 64)
        root = data["traces"]["live"][0]

        self.assertEqual((root["literal_line"], root["literal_column"]), live)
        self.assertEqual(root["context_kind"], "method")
        self.assertEqual(root["method_name"], "target")
        self.assertEqual(root["method_line"], line_of(source, "void target() {"))
        self.assertEqual(root["method_end_line"], line_of(source, "    }\n\n    void caller() {"))
        # `.url(` inside the comment and inside the fake string is not a request marker
        self.assertEqual(root.get("request_markers", []), [])
        # only the real call in caller(); the `target();` in the comment is not a caller
        self.assertEqual([(caller["line"], caller["method_name"]) for caller in root["callers"]],
                         [(line_of_after(source, "void caller() {", "target();"), "caller")])
        self.assertNotIn(line_of_after(source, "// void ghost() {", "target();"),
                         [caller["line"] for caller in root["callers"]])

    def test_commented_url_position_reports_comment_context(self):
        source = MESSY_SOURCE
        literal = position_of(source, "https://api.example.test/v1/comment-only")
        data = trace_source(source, {"comment": [literal]}, 64)
        self.assertEqual(len(data["traces"]["comment"]), 1)
        root = data["traces"]["comment"][0]
        self.assertEqual((root["literal_line"], root["literal_column"]), literal)
        self.assertEqual(root["context_kind"], "comment")
        self.assertIsNone(root.get("method_name"))
        self.assertEqual(root.get("field_links", []), [])
        self.assertEqual(root.get("callers", []), [])

    def test_string_embedded_declaration_is_not_a_method(self):
        source = MESSY_SOURCE
        literal = position_of(source, "https://api.example.test/v1/quoted")
        data = trace_source(source, {"quoted": [literal]}, 64)
        root = data["traces"]["quoted"][0]
        self.assertEqual(root["context_kind"], "field_initializer")
        self.assertEqual(root["field_name"], "doc")
        self.assertIsNone(root.get("method_name"))

    def test_bare_field_reads_respect_shadowing(self):
        source = SHADOW_SOURCE
        literal = position_of(source, "https://api.example.test/v1/base")
        data = trace_source(source, {"base": [literal]}, 64)
        self.assertEqual(len(data["traces"]["base"]), 1)
        root = data["traces"]["base"][0]

        self.assertEqual((root["literal_line"], root["literal_column"]), literal)
        self.assertEqual(root["context_kind"], "field_initializer")
        self.assertEqual(root["field_name"], "baseUrl")
        self.assertIsNone(root.get("method_name"))
        self.assertEqual(root["request_markers"], [])
        self.assertEqual(root["callers"], [])

        links = root["field_links"]
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["field_name"], "baseUrl")
        self.assertEqual(link["resolution"], "direct_field_initializer")

        clean_read = line_of_after(source, "String clean() {", "return baseUrl;")
        param_read = line_of_after(source, "String shadowedByParameter(String baseUrl) {", "return baseUrl;")
        local_read = line_of_after(source, "String shadowedByLocal() {", "return baseUrl;")
        this_read = line_of(source, "return this.baseUrl;")
        uses = {use["line"]: use for use in link["uses"]}
        # shadowed bare reads (parameter and local) are dropped; unshadowed and this.-qualified reads stay
        self.assertEqual(set(uses), {clean_read, this_read})
        self.assertEqual(uses[clean_read]["method_name"], "clean")
        self.assertEqual(uses[clean_read]["method_line"], line_of(source, "String clean() {"))
        self.assertEqual(uses[this_read]["method_name"], "explicitThis")
        self.assertEqual(uses[this_read]["method_line"], line_of(source, "String explicitThis() {"))
        self.assertNotIn(param_read, uses)
        self.assertNotIn(local_read, uses)
        for use in uses.values():
            self.assert_use_shape(use)
            self.assertEqual(use.get("request_markers", []), [])
            self.assertEqual(use.get("callers", []), [])

    def test_max_items_caps_retained_items_and_counts_every_item(self):
        source = CONSTRUCTOR_SOURCE
        literal = position_of(source, "https://api.grok.test/v1/base")

        full = trace_source(source, {"base": [literal]}, 64)
        self.assertEqual(full["items"], count_items(full))
        self.assertEqual(full["items"], 4)  # root + field-link + two field-uses
        self.assertEqual(full["omitted"], 0)
        self.assertFalse(full["truncated"])

        capped = trace_source(source, {"base": [literal]}, 2)
        self.assertLessEqual(capped["items"], 2)
        self.assertEqual(capped["items"], count_items(capped))
        self.assertGreaterEqual(capped["omitted"], 1)
        self.assertTrue(capped["truncated"])
        for roots in capped["traces"].values():
            for root in roots:
                for link in root.get("field_links", []):
                    for use in link.get("uses", []):
                        self.assert_use_shape(use)

        smallest = trace_source(source, {"base": [literal]}, 1)
        self.assertLessEqual(smallest["items"], 1)
        self.assertEqual(smallest["items"], count_items(smallest))
        self.assertGreaterEqual(smallest["omitted"], 1)
        self.assertTrue(smallest["truncated"])

    def test_cap_is_shared_across_literal_keys(self):
        source = OVERLOAD_SOURCE
        data = trace_source(source, {"text": [position_of(source, "https://api.example.test/v1/fetch-text")],
                                     "id": [position_of(source, "https://api.example.test/v1/fetch-id")]}, 1)
        self.assertLessEqual(data["items"], 1)
        self.assertEqual(data["items"], count_items(data))
        self.assertGreaterEqual(data["omitted"], 1)
        self.assertTrue(data["truncated"])
        self.assertLessEqual(sum(len(roots) for roots in data["traces"].values()), 1)

    def test_constructor_does_not_bind_assignments_inside_anonymous_class(self):
        source = '''
class Client {
    String baseUrl;
    Client(String value) {
        Runnable callback = new Runnable() {
            String baseUrl;
            public void run() { this.baseUrl = value; }
        };
    }
    static Client create() { return new Client("https://api.example.test/anonymous"); }
    String read() { return this.baseUrl; }
}
'''
        result = trace_source(source, {"url": [position_of(source, "https://api.example.test/anonymous")]}, 32)
        self.assertEqual(result["traces"]["url"][0].get("field_links", []), [])

    def test_qualified_external_constructor_is_not_bound_by_simple_name(self):
        source = '''
class Client {
    String baseUrl;
    Client(String value) { this.baseUrl = value; }
    Object create() { return new external.Client("https://api.example.test/external"); }
    String read() { return this.baseUrl; }
}
'''
        result = trace_source(source, {"url": [position_of(source, "https://api.example.test/external")]}, 32)
        self.assertEqual(result["traces"]["url"][0].get("field_links", []), [])

    def test_field_reassignments_are_not_reported_as_reads(self):
        source = '''
class Client {
    String baseUrl = "https://api.example.test/reassigned";
    String read() {
        this.baseUrl = "changed";
        this.baseUrl += "/suffix";
        return this.baseUrl;
    }
}
'''
        result = trace_source(source, {"url": [position_of(source, "https://api.example.test/reassigned")]}, 32)
        uses = result["traces"]["url"][0]["field_links"][0]["uses"]
        self.assertEqual([use["line"] for use in uses], [line_of(source, "return this.baseUrl;")])

    def test_unsupported_and_unbalanced_sources_are_not_resolved_java(self):
        cases = [
            ("kotlin", KOTLIN_SOURCE, "https://api.example.test/v1/kotlin"),
            ("smali", SMALI_SOURCE, "https://api.example.test/v1/smali"),
            ("unterminated", UNTERMINATED_SOURCE, "https://api.example.test/v1/unterminated"),
            ("extra-brace", EXTRA_BRACE_SOURCE, "https://api.example.test/v1/extra-brace"),
        ]
        for key, source, url in cases:
            with self.subTest(case=key):
                literal = position_of(source, url)
                data = trace_source(source, {key: [literal]}, 32)
                roots = data["traces"][key]
                self.assertEqual(len(roots), 1)
                root = roots[0]
                self.assertNotEqual(root["context_kind"], "method")
                self.assertIsNone(root.get("method_name"))
                self.assertEqual(root.get("field_links", []), [])
                self.assertEqual(root.get("callers", []), [])


if __name__ == "__main__":
    unittest.main()
