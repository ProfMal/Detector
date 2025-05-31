from __future__ import annotations
from npm_pipeline.classes.object import Object


class PDGNode:
    def __init__(self, node_id):
        self.node_id = node_id  # node id
        self.source_pdg = None  # the source pdg
        self.node_type = None
        self.line_number: int | None = None
        self.line_number_end: int | None = None
        self.column_number: int | None = None
        self.column_number_end: int | None = None
        self.name = None
        self.filename = None
        self.code = None
        self.sensitive_node = False
        self.is_entrance = False
        self.is_return = False
        self.call_type = None
        self.function_behavior = None
        self.node_full_name: tuple[Object, list[str]] | None = None
        self.return_value = None
        self.branch = False
        self.sensitive_dict = None
        self.sensitive_degree = 0.5

    def __lt__(self, other):
        return self.line_number < other.line_number

    def set_source_pdg(self, pdg_id):
        self.source_pdg = pdg_id

    def get_source_pdg(self):
        return self.source_pdg

    def get_call_type(self):
        return self.call_type

    def set_call_type(self, call_type):
        self.call_type = call_type

    def get_behavior_of_call(self):
        return self.function_behavior

    def set_behavior_of_call(self, diagram):
        self.function_behavior = diagram

    def get_id(self):
        return self.node_id

    def get_node_type(self):
        return self.node_type

    def set_node_type(self, label):
        self.node_type = label

    def get_line_number(self) -> int:
        return self.line_number

    def set_line_number(self, line_number: int | None):
        self.line_number = line_number

    def get_line_number_end(self) -> int:
        return self.line_number_end

    def set_line_number_end(self, line_number_end: int | None):
        self.line_number_end = line_number_end

    def get_column_number(self) -> int:
        return self.column_number

    def set_column_number(self, column_number: int | None):
        self.column_number = column_number

    def get_column_number_end(self):
        return self.column_number_end

    def set_column_number_end(self, column_number_end: int | None):
        self.column_number_end = column_number_end

    def set_sensitive_node(self, bool_value):
        self.sensitive_node = bool_value

    def is_sensitive_node(self):
        return self.sensitive_node

    def set_entrance(self, bool_value):
        self.is_entrance = bool_value

    def is_entrance(self):
        return self.is_entrance

    def set_is_return(self, bool_value):
        self.is_return = bool_value

    def is_return_value(self):
        return self.is_return

    def set_file_name(self, filename):
        self.filename = filename

    def get_file_name(self) -> str:
        return self.filename

    def set_node_full_name(self, node_full_name):
        self.node_full_name = node_full_name

    def get_node_full_name(self):
        return self.node_full_name

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_code(self, code):
        self.code = code

    def get_code(self):
        return self.code

    def set_return_value(self, return_value):
        self.return_value = return_value

    def get_return_value(self):
        return self.return_value

    def set_the_branch(self):
        self.branch = True

    def is_branch(self):
        return self.branch

    def set_sensitive_dict(self, value):
        self.sensitive_dict = value

    def get_sensitive_dict(self):
        return self.sensitive_dict

    def set_sensitive_degree(self, value):
        self.sensitive_degree = value

    def get_sensitive_degree(self):
        return self.sensitive_degree
