import os
import logging

from .plugin import SimStatePlugin
from ..storage.file import SimFileConcrete
from ..errors import SimMergeError, SimFilesystemError

l = logging.getLogger('angr.state_plugins.filesystem')

class SimDirectory(SimStatePlugin):
    """
    This is the base class for directories in angr's emulated filesystem. An instance of this class or a subclass will
    be found as ``state.fs``, representing the root of the filesystem.

    :ivar files:    A mapping from filename to file that this directory contains.
    """
    def __init__(self, files=None, writable=True, parent=None, pathsep='/'):
        super(SimDirectory, self).__init__()
        self.files = files
        self.writable = writable
        self.parent = parent if parent is not None else self
        self.pathsep = pathsep
        self.files['.'] = self
        self.files['..'] = self.parent

    def __len__(self):
        return len(self.files)

    def lookup(self, path, writing=False):
        """
        Look up the file or directory at the end of the given path.
        This method should be called on the current working directory object.

        :param str path:        The path to look up
        :param bool writing:    Whether the operation desired requires write permissions
        :returns:               The SimDirectory or SimFile object specified, or None if not found, or False if writing
                                was requested and the target is nonwritable
        """
        if len(path) == 0:
            return None
        if path[0] == self.pathsep:
            # lookup the filesystem root
            root = self
            while root.parent is not root:
                root = root.parent
            return root._lookup(path[1:], writing)
        else:
            return self._lookup(path, writing)

    def _lookup(self, path, writing):
        while path.startswith(self.pathsep):
            path = path[1:] 

        if len(path) == 0:
            if writing and not self.writable:
                return False
            return self

        for fname, simfile in self.files.iteritems():
            if path.startswith(fname):
                if len(path) == len(fname):
                    if writing and not simfile.writable:
                        return False
                    return simfile
                elif path[len(fname)] == self.pathsep:
                    if isinstance(simfile, SimDirectory):
                        return simfile._lookup(path[len(fname)+1:])
                    else: # TODO: symlinks
                        return None

        return None

    def insert(self, path, simfile):
        """
        Add a file to the filesystem.
        This method should be called on the current working directory object.

        :param str path:    The path to insert the new file at
        :param simfile:     The new file or directory
        :returns:           A boolean indicating whether the operation succeeded
        """
        while len(path) > 1 and path[-1] == self.pathsep:
            path = path[:-1]

        if self.pathsep not in path:
            if path in self.files:
                return False
            if isinstance(simfile, SimDirectory):
                if simfile.parent is simfile:
                    simfile.parent = self
                    simfile.pathsep = self.pathsep
                else:
                    l.error("Trying to add directory to filesystem which already has a parent")

            self.files[path] = simfile
            simfile.set_state(self.state)
            return True
        else:
            lastsep = path.rindex(self.pathsep) + 1
            head, tail = path[:lastsep], path[lastsep:]
            parent = self.lookup(head, True)

            if not parent:
                return False
            return parent.insert(tail, simfile)

    def remove(self, path):
        """
        Remove a file from the filesystem. If the target is a directory, the directory must be empty.
        This method should be called on the current working directory object.

        :param str path:    The path to remove the file at
        :returns:           A boolean indicating whether the operation succeeded
        """
        while len(path) > 1 and path[-1] == self.pathsep:
            # TODO: when symlinks exist this will need to be fixed to delete the target of the
            # symlink instead of the link itself
            path = path[:-1]

        if self.pathsep not in path:
            if path in ('.', '..'):
                return False
            if path not in self.files:
                return False
            if isinstance(self.files[path], SimDirectory) and len(self.files[path]) != 2:
                return False

            del self.files[path]
            return True
        else:
            lastsep = path.rindex(self.pathsep) + 1
            head, tail = path[:lastsep], path[lastsep:]
            parent = self.lookup(head, True)

            if not parent:
                return False
            return parent.remove(tail)

    @SimStatePlugin.memo
    def copy(self, memo):
        return SimDirectory(
                files={x: y.copy(memo) for x, y in self.files.iteritems()},
                writable=self.writable,
                parent=self.parent.copy(memo),
                pathsep=self.pathsep)

    def merge(self, others, conditions, ancestor=None):
        new_files = {path: (simfile, [], []) for path, simfile in self.files.iteritems() if path not in ('.', '..')}
        for other, condition in zip(others, conditions):
            if type(other) is not type(self):
                raise SimMergeError("Can't merge filesystem elements of disparate types")
            for path, simfile in other.files.iteritems():
                if path in ('.', '..'):
                    continue
                if path not in new_files:
                    l.warning("Cannot represent the conditional creation of files")
                    new_files[path] = (simfile, [], [])
                else:
                    new_files[path][1].append(simfile)
                    new_files[path][2].append(condition)

        for k in new_files:
            new_files[k][0].merge(new_files[k][1], new_files[k][2], ancestor)
            new_files[k] = new_files[k][0]
        new_files['.'] = self
        new_files['..'] = self.parent
        self.files = new_files

    def widen(self, others):
        new_files = {path: [simfile] for path, simfile in self.files.iteritems() if path not in ('.', '..')}
        for other in others:
            if type(other) is not type(self):
                raise SimMergeError("Can't merge filesystem elements of disparate types")
            for path, simfile in other.files.iteritems():
                if path in ('.', '..'):
                    continue
                if path not in new_files:
                    new_files[path] = [simfile]
                else:
                    new_files[path].append(simfile)

        for k in new_files:
            new_files[k][0].widen(new_files[k][1:])
            new_files[k] = new_files[k][0]
        new_files['.'] = self
        new_files['..'] = self.parent
        self.files = new_files

class SimDirectoryConcrete(SimDirectory):
    """
    A SimDirectory that forwards its requests to the host filesystem

    :param host_path:   The path on the host filesystem to provide
    :param writable:    Whether to allow mutation of the host filesystem by the guest
    """
    def __init__(self, host_path, writable=False, pathsep='/', host_root=None, parent=None):
        super(SimConcreteDirectory, self).__init__(files={}, writable=writable, parent=parent, pathsep=pathsep)
        self.host_path = os.path.realpath(host_path)
        self.host_root = self.host_path if host_root is None else host_root

    def _lookup(self, path, writing):
        partial_path = self.host_path
        for i, pathkey in enumerate(path.split(self.pathsep)):
            if partial_path == self.host_root and pathkey == '..':
                target = self.pathsep.join(path.split(self.pathsep)[i+1:])
                return self.parent._lookup(target, writing)
            if not os.path.isdir(partial_path):
                return None

            partial_path = os.path.realpath(partial_path + self.pathsep + pathkey)

        if writing and not self.writable:
            return False

        if os.path.isdir(partial_path):
            f = SimDirectoryConcrete(host_path=partial_path, writable=self.writable, host_root=self.host_root, parent=self.parent)
            f.set_state(self.state)
            return f
        elif os.path.isfile(partial_path):
            try:
                f = SimFileConcrete(host_path=partial_path, writable=self.writable)
                f.set_state(self.state)
                return f
            except OSError:
                return None
        else:
            raise SimFilesystemError("Can't handle something other than a file or directory in a concrete filesystem")

    def insert(self, path, simfile):
        if self.pathsep in path:
            return super(SimDirectoryConcrete, self).insert(path, simfile)
        else:
            fullpath = os.path.join(self.host_path, path)
            if os.path.exists(fullpath):
                return False
            with open(fullpath, 'w') as fp:
                fp.write(simfile.concretize())
            return True

    def remove(self, path):
        if self.pathsep in path:
            return super(SimDirectoryConcrete, self).remove(path)
        else:
            fullpath = os.path.join(self.host_path, path)
            if not os.path.exists(fullpath):
                return False
            if os.path.isdir(fullpath):
                try:
                    os.rmdir(fullpath)
                except OSError:
                    return False
                return True
            elif os.path.isfile(fullpath):
                try:
                    os.unlink(fullpath)
                except OSError:
                    return False
                return True
            else:
                raise SimFilesystemError("Can't handle anything but files and directories in concrete filesystem")
