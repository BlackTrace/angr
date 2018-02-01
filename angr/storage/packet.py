import claripy

class SimPacket(object):
    """
    An individual packet of data. This is a base class for representing several kinds of packet data.
    """
    max_length = None
    sym_length = None

    def decompose(self):
        """
        Return data and constraints necessary to represent this packet in a flat address space
        """
        raise NotImplementedError

    def concretize(self, state):
        """
        Return a string for the packet satisfying the constraints currently on the state
        """
        raise NotImplementedError

    def concat(self, *others):
        members = sum(x.members if type(x) is SimPacketConcat else [x] for x in [self] + others)
        return SimPacketConcat(members)

class SimPacketConstant(SimPacket):
    def __init__(self, string):
        self.string = string
        self.max_length = len(string)
        self.sym_length = claripy.BVV(self.max_length, 64)

    def concretize(self, state):
        return self.string

class SimPacketString(SimPacket):
    pass # variable length string with character membership restrictions

class SimPacketInteger(SimPacket): # TODO: unsigned, other representations
    def __init__(self, state, name, bits):
        self.max_length = len(str(2**bits - 1)) + 1
        self.integer = state.solver.BVS(name, bits)

    def concretize(self, state):
        return str(state.solver.eval(self.integer))

class SimPacketConcat(SimPacket):
    def __init__(self, members):
        self.members = members
        self.max_length = sum(x.max_length for x in self.members)
        self.sym_length = sum(x.sym_length for x in self.members)

    def concretize(self, state):
        return ''.join(member.concretize(state) for member in self.members)
