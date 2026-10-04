"""Independent pinned Release 18 identity/reroute NAS recipes; no SDK codecs."""
import copy
from n3iwf_ngap_reference import unpack


def fields(recipe):
    return recipe['value']['value']['value']['protocolIEs']


def bits(value, length):
    return {'bits': f'{value:x}', 'length': length}


def extend_identity_reroute(reference, recipes, record):
    bindings = {
        'amf_set_id': ('InitialUEMessage', 3, 'AMFSetID', 'ignore'),
        'fiveg_s_tmsi': ('InitialUEMessage', 26, 'FiveG-S-TMSI', 'reject'),
        'reroute': ('InitialUEMessage', 171, 'SourceToTarget-AMFInformationReroute', 'ignore'),
        'masked_imeisv': ('DownlinkNASTransport', 34, 'MaskedIMEISV', 'ignore'),
        'extended_old_amf': ('DownlinkNASTransport', 443, 'Extended-AMFName', 'ignore'),
    }
    for message, ident, name, criticality in bindings.values():
        row = next(row for row in reference.rows(message) if row['id'] == ident)
        assert row['presence'] == 'optional' and row['criticality'] == criticality
        assert row['Value']._typeref.called[1] == name

    pool = {key: [] for key in bindings}
    def emit(name, key, value, model):
        message, ident, typename, criticality = bindings[key]
        recipe = copy.deepcopy(recipes[message])
        field = {'id': ident, 'criticality': criticality, 'value': {'type': typename, 'value': value}}
        fields(recipe).append(field)
        pdu = unpack(recipe)
        leaf = next(row['value_hex'] for row in reference.encoded_fields(pdu) if row['id'] == ident)
        record(name, recipe, identity_reroute_fields=True, construct=True,
               identity_field_key=key, field_hex=leaf, **{key: model})
        pool[key].append((field, model))

    for value in [0, 1023] + [1 << i for i in range(10)]:
        emit(f'amf-set-{value}', 'amf_set_id', bits(value, 10), value)
    for set_id in (0, 1, 1023):
        for pointer in (0, 1, 63):
            for tmsi in ('00000000', '01020304', 'ffffffff'):
                emit(f's-tmsi-{set_id}-{pointer}-{tmsi}', 'fiveg_s_tmsi', {
                    'aMFSetID': bits(set_id, 10), 'aMFPointer': bits(pointer, 6),
                    'fiveG-TMSI': {'hex': tmsi}}, {'set_id': set_id, 'pointer': pointer, 'tmsi': tmsi})
    for component, width in [('set_id', 10), ('pointer', 6), ('tmsi', 32)]:
        for bit in range(width):
            model = {'set_id': 17, 'pointer': 9, 'tmsi': '01020304'}
            model[component] = f'{1 << bit:08x}' if component == 'tmsi' else 1 << bit
            emit(f's-tmsi-bit-{component}-{bit}', 'fiveg_s_tmsi', {
                'aMFSetID': bits(model['set_id'], 10), 'aMFPointer': bits(model['pointer'], 6),
                'fiveG-TMSI': {'hex': model['tmsi']}}, model)
    for value in [0, (1 << 64)-1] + [1 << i for i in range(64)]:
        emit(f'masked-imeisv-{value:x}', 'masked_imeisv', bits(value, 64), f'{value:016x}')
    for flags in range(8):
        for pattern in (0, 255, 'ordered'):
            model = {}
            for bit, name, length in [(1, 'configuredNSSAI', 128), (2, 'rejectedNSSAIinPLMN', 32), (4, 'rejectedNSSAIinTA', 32)]:
                if flags & bit:
                    model[name] = bytes((i + bit) % 256 if pattern == 'ordered' else pattern for i in range(length)).hex()
            emit(f'reroute-{flags}-{pattern}', 'reroute', {k: {'hex': v} for k, v in model.items()}, model)
    emit('extended-name-empty', 'extended_old_amf', {}, {})
    for length in (1, 2, 127, 128, 149, 150):
        emit(f'extended-name-visible-{length}', 'extended_old_amf', {'aMFNameVisibleString': 'A'*length}, {'visible': 'A'*length})
        for index, character in enumerate(('A', 'é', '中', '😀')):
            emit(f'extended-name-utf8-{index}-{length}', 'extended_old_amf', {'aMFNameUTF8String': character*length}, {'utf8': character*length})
        emit(f'extended-name-both-{length}', 'extended_old_amf', {
            'aMFNameVisibleString': '~'*length, 'aMFNameUTF8String': '😀'*length},
            {'visible': '~'*length, 'utf8': '😀'*length})
    emit('extended-name-visible-alphabet', 'extended_old_amf', {
        'aMFNameVisibleString': ''.join(chr(i) for i in range(32,127))},
        {'visible': ''.join(chr(i) for i in range(32,127))})

    for key, (message, ident, typename, criticality) in bindings.items():
        first, first_model = pool[key][0]
        last, last_model = pool[key][-1]
        for wrong in (value for value in ('reject', 'ignore', 'notify') if value != criticality):
            recipe = copy.deepcopy(recipes[message])
            changed = copy.deepcopy(first)
            changed['criticality'] = wrong
            fields(recipe).append(changed)
            record(f'identity-criticality-{key}-{wrong}', recipe,
                   identity_reroute_fields=True, invalid_identity_id=ident,
                   identity_field_key=key)
        recipe = copy.deepcopy(recipes[message])
        fields(recipe).extend([copy.deepcopy(first), copy.deepcopy(last)])
        record(f'identity-duplicate-{key}', recipe, identity_reroute_fields=True,
               identity_duplicate_id=ident, identity_field_key=key,
               **{f'first_{key}': first_model, f'last_{key}': last_model})

    for message, keys in [('InitialUEMessage', ['amf_set_id', 'fiveg_s_tmsi', 'reroute']),
                          ('DownlinkNASTransport', ['masked_imeisv', 'extended_old_amf'])]:
        recipe = copy.deepcopy(recipes[message])
        model = {}
        if message == 'DownlinkNASTransport':
            fields(recipe).append({'id':48, 'criticality':'reject', 'value':{'type':'AMFName','value':'AMF-OLD'}})
            model['old_amf'] = 'AMF-OLD'
        for key in keys:
            field, value = pool[key][-1]
            fields(recipe).append(copy.deepcopy(field))
            model[key] = value
        record(f'identity-combined-{message}', recipe, identity_reroute_fields=True, construct=True, **model)
        fields(recipe).reverse()
        record(f'identity-combined-reordered-{message}', recipe, identity_reroute_fields=True, **model)
