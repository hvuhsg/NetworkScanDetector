from tinydb import TinyDB

__all__ = ["pkg_to_json", "get_db"]

class JsonPacket:
    def __init__(self, pkt):
        self.pkt = pkt
        self.name = "JsonPacket"
        self.fields_desc = []
        self.json_valid_types = (dict, list, str, int, float, bool, None)

    def build_done(self):
        return self._jsonize_packet()

    def _jsonize_packet(self):
        layers = [layer for layer in self._walk_layers()]
        out = []
        for layer in layers:
            layer_name = layer.name if layer.name else layer.__name__
            out.append({layer_name: self._serialize_fields(layer, {})})
        return out

    def _walk_layers(self):
        i=1
        layer = self.pkt.getlayer(i)
        while layer:
            yield layer
            i += 1
            layer = self.pkt.getlayer(i)

    def _serialize_fields(self, layer, serialized_fields={}):
        if hasattr(layer, "fields_desc"):
            for field in layer.fields_desc:
                self._extract_fields(layer, field, serialized_fields)
        return serialized_fields

    def _extract_fields(self, layer, field, extracted={}):
        value = layer.__getattr__(field.name)
        if type(value) in self.json_valid_types:
            if type(value) is list:
                value = [tuple(j.decode() if type(j) is bytes else str(j) for j in i) if type(i) is tuple else i for i in value]
            extracted.update({field.name: value})
        else:
            if type(value) is bytes:
                value = "<BYTES>"
            extracted.update({field.name: str(value)})
            # self._serialize_fields(field, local_serialized)

    def _serialize_iterables(self, iter):
        return tuple(i.decode() if type(i) is bytes else i for i in iter)


def pkg_to_json(pkg):
    """
    This function convert a Scapy packet to JSON

    :param pkg: A scapy package
    :type pkg: objects

    :return: A JSON data
    :rtype: dict()
    """
    packet = JsonPacket(pkg)
    json_packet = packet.build_done()
    json_packet = {list(layer.keys())[0]: list(layer.values())[0] for layer in json_packet}
    json_packet.pop("Raw", None)
    return json_packet


def get_db():
    return TinyDB("data/db.json")
