# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: router_bridge.proto
# Protobuf Python Version: 5.29.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    1,
    '',
    'router_bridge.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13router_bridge.proto\x12\rrouter_bridge\"\x8e\x01\n\x0fProtocolMessage\x12:\n\x10interface_update\x18\x01 \x01(\x0b\x32\x1e.router_bridge.InterfaceUpdateH\x00\x12\x34\n\rrouter_packet\x18\x02 \x01(\x0b\x32\x1b.router_bridge.RouterPacketH\x00\x42\t\n\x07message\"?\n\x0fInterfaceUpdate\x12,\n\ninterfaces\x18\x01 \x03(\x0b\x32\x18.router_bridge.Interface\"2\n\tInterface\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\n\n\x02ip\x18\x02 \x01(\r\x12\x0b\n\x03mac\x18\x03 \x01(\x0c\"/\n\x0cRouterPacket\x12\x11\n\tinterface\x18\x01 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'router_bridge_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_PROTOCOLMESSAGE']._serialized_start=39
  _globals['_PROTOCOLMESSAGE']._serialized_end=181
  _globals['_INTERFACEUPDATE']._serialized_start=183
  _globals['_INTERFACEUPDATE']._serialized_end=246
  _globals['_INTERFACE']._serialized_start=248
  _globals['_INTERFACE']._serialized_end=298
  _globals['_ROUTERPACKET']._serialized_start=300
  _globals['_ROUTERPACKET']._serialized_end=347
# @@protoc_insertion_point(module_scope)