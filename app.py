"""
The MIT License (MIT)

Copyright (c) 2016 Dave Parsons

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the 'Software'), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import print_function
import json
import os
import shutil
import subprocess
import sys
import time
from bottle import run, get, delete, post, patch, request, response, static_file, error
from configobj import ConfigObj
from pyvmxdict import VMDict

__author__ = 'Dave Parsons'
__version__ = '1.0.0'
__license__ = 'MIT'

VIX_SHAREDFOLDER_WRITE_ACCESS = 4

platform = ''
names = {}
vms = {}

DEFAULT_VM_PATH = ''
DEFAULT_PARENT_VM_PATH = ''
DEFAULT_LOG_PATH = ''
PORT = ''
VMRUN = ''
VMTYPE = ''


if sys.version_info < (2, 7):
    sys.stderr.write('You need Python 2.7 or later\n')
    sys.exit(1)


def log_date_time_string():
    """Return the current time formatted for logging."""
    now = time.time()
    year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
    s = "%02d/%3s/%04d %02d:%02d:%02d" % (
        day, monthname[month], year, hh, mm, ss)
    return s


weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

monthname = [None,
             'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']


def log_message(msgfmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                         ('127.0.0.1',
                          log_date_time_string(),
                          msgfmt % args))


def getstringpath():
    return os.path.dirname(os.path.realpath(sys.argv[0]))


def isfile(filename):
    return os.path.isfile(filename)


def isfolder(foldername):
    return os.path.isdir(foldername)


def joinpath(folder, filename):
    return os.path.join(folder, filename)


def runcmd(cmd, strip=True):

    # vmrun does not return any exit codes and all errors are in stdout!
    command = VMRUN + VMTYPE + cmd
    log_message('%s %s', 'VMRUN Command: ', command)
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    stdout = proc.stdout.readlines()

    if any("Error" in s for s in stdout):
        code = 500
    else:
        code = 200

    if len(stdout) > 0:
        output = ''.join(str(l) for l in stdout)
    else:
        output = ''

        log_message('%s %s', 'VMRUN Output: ', output)

    if strip:
        output = output.replace('\n', '').replace('\r', '')
    return code, output


def symlink(src, dest):
    command = 'mklink /d "' + dest + '" "' + src + '"'
    log_message('%s %s', 'Windows creating symlink: ', command)
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    stdout = proc.stdout.readlines()
    log_message('%s %s', 'Windows creating symlink: ', stdout)


@get('/api')
def api():

    # TODO: Return configuration via JSON
    # Return the API version

    return __version__


@get('/api/config')
def api():

    # TODO: Return configuration via HTML template
    # Return the config details (appcatalyst.conf)
    # DEFAULT_VM_PATH
    # DEFAULT_PARENT_VM_PATH
    # DEFAULT_LOG_PATH
    # PORT
    # VMRUN
    # VMTYPE
    return


@get('/api/vms')
def get_vms():

    # Return the names dict keys in non-JSON text form:
    # ["photon1", "photons2", ...]
    # Ignore the "tags" parameters as not used in AppCatalyst previews
    output = ''
    for key in names.keys():
        output = output + '"' + key + '",'
    output = '[' + output[:-1] + ']'
    response.body = output
    response.content_type = 'text/plain; charset=utf-8'
    response.status = 200
    return response


@post('/api/vms')
def post_vms():

    # Create a new cloned VM from default or specified source
    body = json.load(request.body)
    destvmx = ''
    output = ''

    if 'id' in body:
        if 'sourceReference' in body:
            destvmx = joinpath(joinpath(DEFAULT_VM_PATH, body['id']), os.path.basename(body['sourceReference']))
        else:
            destvmx = joinpath(joinpath(DEFAULT_VM_PATH, body['id']), body['id'] + '.vmx')
    else:
        response.body = '{"code": 500, "message": "EOF"}'
        response.body = 500

    if 'parentId' in body:
        srcvmx = joinpath(joinpath(DEFAULT_VM_PATH, body['parentId']), body['parentId'] + '.vmx')
        code, output = runcmd('clone ' + srcvmx + ' ' + destvmx + ' full')
    elif 'sourceReference' in body:
        srcvmx = body['sourceReference']
        try:
            srcdir = os.path.dirname(srcvmx)
            destdir = joinpath(DEFAULT_VM_PATH, body['id'])
            if platform == 'windows':
                symlink(srcdir, destdir)
            else:
                os.makedirs(destdir)
                os.symlink(srcvmx, destvmx)
            code = 200
        except OSError:
            code = 500
            output = "Failed to create VMX symlink"
    else:
        srcvmx = DEFAULT_PARENT_VM_PATH
        code, output = runcmd('clone ' + srcvmx + ' ' + destvmx + ' full')

    # Check response code from the vmrun procedure & return to caller
    if code == 200:
        if 'parentId' in body:
            response.body = '{"id": "' + body['id'] + \
                            '", "parentId": "' + body['parentId'] + '", "name": "", "tag": "", "sourceReference": ""}'
        elif 'sourceReference' in body:
            response.body = '{"id": "' + body['id'] + \
                            '", "parentId": "", "name": "", "tag": "", "sourceReference": "' + \
                            body['sourceReference'] + '"}'
        else:
            response.body = '{"id": "' + body['id'] + \
                            '", "parentId": "", "name": "", "tag": "", "sourceReference": ""}'

        names[body['id']] = destvmx
        vmx = ConfigObj(destvmx)
        vms[body['id']] = vmx
        with open('vmInventory', 'w') as f:
            json.dump(names, f)
        response.status = code
    elif code == 500:
        response.body = '{"code": 500, "message": "' + output + '"}'
        response.status = code
    else:
        pass

    response.content_type = 'application/json; charset=utf-8'
    return response


@get('/api/vms/<vmid>')
def get_vms_id(vmid):

    # Check id is valid
    output = ''
    if vms:
        for key, value in vms.items():
            if vmid == key:
                output = '{"id": "' + key + '", "name": "' + vms[key]['displayname'] + '", "tag": ""}'
            response.status = 200
    else:
        output = '{}'
        response.status = 500

    response.body = output
    response.content_type = 'application/json; charset=utf-8'
    return response


@delete('/api/vms/<vmid>')
def del_vms_id(vmid):

    # Delete the VM from inventory
    # code, output = runcmd('stop ' + names[vmid] + ' hard')
    code, output = runcmd('deleteVM ' + names[vmid])
    try:
        shutil.rmtree(joinpath(DEFAULT_VM_PATH, vmid), True)
    except OSError:
        code = 500
        output = 'Failed to delete VMX folder'
    if code == 200:
        response.status = 204
    elif code == 500:
        response.body = '{"code": 500, "message": "' + output + '"}'
        response.status = code
    else:
        pass

    # Remove the relevant dict entries
    if vmid in names:
        del names[vmid]
        del vms[vmid]

    with open('vmInventory', 'w') as f:
        json.dump(names, f)
        f.close()

    response.content_type = 'application/json; charset=utf-8'
    return response


@get('/api/vms/power/<vmid>')
def get_vms_power_id(vmid):

    # List the running VMs and see if id is one of them
    code, message = runcmd('list')
    if code == 200:
        if vmid in message:
            response.body = '{"code": 200, "message": "powered on"}'
        else:
            response.body = '{"code": 200, "message": "powered off"}'
        response.status = code
    elif code == 500:
        response.body = '{"code": 500, "message": "' + message + '"}'
        response.status = code
    else:
        pass

    response.content_type = 'application/json; charset=utf-8'
    return response


@patch('/api/vms/power/<vmid>')
def patch_vms_power_id(vmid):

    # Power operations for the VM
    body = request.body.read()
    powerop = ''
    powersubop = ''
    if body == 'on':
        powerop = 'start'
        powersubop = 'nogui'
        body = '{"code": 200, "message": "The VM is powered on."}'
    elif body == 'off':
        powerop = 'stop'
        powersubop = 'hard'
        body = '{"code": 200, "message": "The VM is powered off."}'
    elif body == 'shutdown':
        powerop = 'stop'
        powersubop = 'soft'
        body = '{"code": 200, "message": "The VM is shut down."}'
    elif body == 'suspend':
        powerop = 'suspend'
        powersubop = ''
        body = '{"code": 200, "message": "The VM is suspended."}'
    elif body == 'pause':
        powerop = 'pause'
        powersubop = ''
        body = '{"code": 200, "message": "The VM is paused."}'
    elif body == 'unpause':
        powerop = 'unpause'
        powersubop = ''
        body = '{"code": 200, "message": "The VM is unpaused."}'
    else:
        body = '{"code": 500, "message": "The op name is not supported."}'

    # Run the command
    code, output = runcmd(powerop + ' ' + names[vmid] + ' ' + powersubop)

    # Check response code from the vmrun procedure & return to caller
    if code == 200:
        response.body = body
    elif code == 500:
        response.body = '{"code": 500, "message": "VIX Error: ' \
                        'The virtual machine needs to be powered on, code: 3006, operation: vm.' \
                        + powerop + '"}'
    else:
        pass

    response.content_type = 'application/json; charset=utf-8'
    response.status = code
    return response


@get('/api/vms/<vmid>/folders')
def get_vms_folders_id(vmid):
    # Retrieve shared folders
    code, output = runcmd('readVariable ' + names[vmid] + ' runtimeConfig sharedFolder.maxNum')

    # Check response code from the vmrun procedure & return to caller
    if code == 200:
        # Iterate through guestName variables
        body = "["
        if output:
            j = int(output)
            for i in range(0, j):
                code, output = runcmd('readVariable ' + names[vmid] + ' runtimeConfig sharedFolder'
                                      + str(i) + '.guestName')
                body = body + '"' + output + '",'
        if len(body) > 1:
            body = body[:-1]
        body += ']'
        response.body = body
        response.content_type = 'text/plain; charset=utf-8'
    elif code == 500:
        response.body = '{"code": 500, "message": ' + output + '"}'
        response.content_type = 'application/json; charset=utf-8'
    else:
        pass

    response.status = 200
    return response


@patch('/api/vms/<vmid>/folders')
def patch_vms_id_folders(vmid):

    # Toggle shared folders on/off
    body = request.body.read()
    folderop = ''
    if body == 'true':
        folderop = 'enableSharedFolders '
    elif body == 'false':
        folderop = 'disableSharedFolders '
    else:
        # TODO: Correct the processing here for invalid value
        # output = '{"code": 500, "message": "The op name is not supported."}'
        pass

    # Run the command
    code, output = runcmd(folderop + names[vmid])

    # Check response code from the vmrun procedure & return to caller
    if code == 200:
        response.body = '{"code": 200, "message": "' + body + '"}'
    elif code == 500:
        response.body = '{"code": 500, "message": ' + output + '"}'
    else:
        pass

    response.content_type = 'application/json; charset=utf-8'
    response.status = code
    return response


@post('/api/vms/<vmid>/folders')
def post_vms_id_folders_id(vmid):
    # Add a new shared folder
    body = json.load(request.body)
    if {'guestPath', 'hostPath', 'flags'} == set(body):

        # Run the command
        code, output = runcmd('addSharedFolder ' + names[vmid] + ' ' + body['guestPath'] + ' ' + body['hostPath'])

        # Check response code from the vmrun procedure & return to caller
        if code == 200:
            response.body = '{"guestPath": "' + body['guestPath'] + '", "hostPath": "' \
                            + body['hostPath'] + '", "flags": 4}'
        elif code == 500:
            response.body = '{"code": 500, "message": ' + output + '"}'
        else:
            pass
        response.status = code
    else:
        response.body = '{"code": 500, "message": "EOF"}'
        response.status = 500

    response.content_type = 'application/json; charset=utf-8'
    return response


@get('/api/vms/<vmid>/folders/<folderid>')
def get_vms_id_folders_id(vmid, folderid):
    # Retrieve shared folders
    code, output = runcmd('readVariable ' + names[vmid] + ' runtimeConfig sharedFolder.maxNum')

    # Check response code from the vmrun procedure & return to caller
    if code == 200:
        # Iterate through guestName variables
        if output:
            j = int(output)
            for i in range(0, j):
                code, guestpath = runcmd('readVariable ' + names[vmid] + ' runtimeConfig sharedFolder'
                                         + str(i) + '.guestName')
                if guestpath == folderid:
                    code, hostpath = runcmd('readVariable ' + names[vmid] + ' runtimeConfig sharedFolder'
                                            + str(i) + '.hostPath')
                    response.body = '{"guestPath": "' + folderid + '", "hostPath": "' + hostpath + '", "flags": 4}'
    elif code == 500:
        response.body = '{"code": 500, "message": ' + output + '"}'
    else:
        pass

    response.content_type = 'application/json; charset=utf-8'
    response.status = 200
    return response


@patch('/api/vms/<vmid>/folders/<folderid>')
def patch_vms_id_folders_id(vmid, folderid):
    # Modify a shared folder
    body = json.load(request.body)
    if {'guestPath', 'hostPath', 'flags'} == set(body):

        # Run the command
        code, output = runcmd('setSharedFolderState ' + names[vmid] + ' ' + body['guestPath']
                              + ' ' + body['hostPath'] + ' writeable')

        # Check response code from the vmrun procedure & return to caller
        if code == 200:
            response.body = '{"guestPath": "' + body['guestPath'] + '", "hostPath": "'\
                            + body['hostPath'] + '", "flags": 4}'
        elif code == 500:
            response.body = '{"code": 500, "message": ' + folderid + ' ' + output + '"}'
        else:
            pass
        response.status = code
    else:
        response.body = '{"code": 500, "message": "EOF"}'
        response.status = 500

    response.content_type = 'application/json; charset=utf-8'
    return response


@delete('/api/vms/<vmid>/folders/<folderid>')
def delete_vms_id_folders_id(vmid, folderid):
    # Delete a shared folder

    # Run the command
    code, output = runcmd('removeSharedFolder ' + names[vmid] + ' ' + folderid)

    # Check response code from the vmrun procedure & return to caller
    if code == 200:
        code = 204
    elif code == 500:
        response.body = '{"code": 500, "message": ' + output + '"}'
    else:
        pass

    response.status = code
    response.content_type = 'application/json; charset=utf-8'
    return response


@get('/api/vms/<vmid>/ipaddress')
def get_vms_getipaddress(vmid):

    # Run the command
    code, output = runcmd('getGuestIPAddress ' + names[vmid] + ' -wait')

    # Check response code from the vmrun procedure & return to caller
    if code == 200:
        response.body = '{"code": 200, "message": "' + output + '"}'
    elif code == 500:
        response.body = '{"code": 500, "message": ' + output + '"}'
    else:
        pass

    response.content_type = 'application/json; charset=utf-8'
    response.status = code
    return response


@get('/')
def server_root():
    # Return swagger-ui index.html
    return static_file('index.html', root='./swagger')


@get('/<filepath:path>')
def server_swagger(filepath):
    # Mapping for swagger-ui static files
    return static_file(filepath, root='./swagger')


@error(500)
def error500():
    # Pass back any 500 Internal Server Errors in JSON and not HTML format
    response.status = 500
    response.body = '{"code": 500, "message": "' + error.traceback.splitlines()[-1] + '"}'
    response.content_type = 'application/json; charset=utf-8'
    return response


def main():

    # TODO: Much of this is not Pythonic and will need more work
    # TODO: Implement a class for the main application to remove globals

    log_message('%s', 'Hello from DSXCatalyst!')
    log_message('%s', '(c) Dave Parsons 2016')

    # Get the underlying OS for configuration data
    global platform
    platform = sys.platform
    if platform == 'darwin':
        platform = 'macos'
    elif platform == 'linux2':
        platform = 'linux'
    elif platform == 'win32':
        platform = 'windows'
    else:
        log_message('%s', 'DSXCatalyst - running on unknown platform')
        sys.exit(1)

    # Read the appcatalyst.conf file and validate parameters
    scriptpath = getstringpath()
    configfile = joinpath(scriptpath, 'appcatalyst.conf')

    if not isfile(configfile):
        log_message('%s', 'DSXCatalyst - appcatalyst.conf not found')
        sys.exit(1)

    config = ConfigObj(configfile)

    global DEFAULT_VM_PATH
    global DEFAULT_PARENT_VM_PATH
    global DEFAULT_LOG_PATH
    global PORT
    global VMRUN
    global VMTYPE

    DEFAULT_VM_PATH = os.path.expanduser(config[platform]['DEFAULT_VM_PATH'])
    DEFAULT_PARENT_VM_PATH = os.path.expanduser(config[platform]['DEFAULT_PARENT_VM_PATH'])
    DEFAULT_LOG_PATH = os.path.expanduser(config[platform]['DEFAULT_LOG_PATH'])
    PORT = config[platform]['PORT']
    VMRUN = config[platform]['VMRUN']
    VMTYPE = config[platform]['VMTYPE']

    log_message('%s %s', 'DEFAULT_VM_PATH = ', DEFAULT_VM_PATH)
    log_message('%s %s', 'DEFAULT_PARENT_VM_PATH = ', DEFAULT_PARENT_VM_PATH)
    log_message('%s %s', 'DEFAULT_LOG_PATH = ', DEFAULT_LOG_PATH)
    log_message('%s %s', 'PORT  = ', PORT)
    log_message('%s %s', 'VMRUN = ', VMRUN + VMTYPE)

    # Get the VMs from the inventory
    global names
    global vms

    # Read or create the vmInventory file
    if isfile('vmInventory'):
        with open('vmInventory', 'r') as f:
            names = json.load(f)
            f.close()
    else:
        with open('vmInventory', 'w') as f:
            f.writelines('{}')
            f.close()

    # Found VMX file so ensure the 2 dicts:
    # names - folder name --> vmx file path
    # vms   - folder name --> vmx file contents
    log_message('%s', 'DSXCatalyst - discovered vms:')
    for name, vmxfile in names.items():
        log_message('%s %s', name, vmxfile)
        if isfile(vmxfile):
            # Read and add guest VMX file to dict
            vmx = VMDict(vmxfile)
            vms[name] = vmx
        else:
            # Remove any missing guests
            del names[name]
            with open('vmInventory', 'w') as f:
                json.dump(names, f)
                f.close()

    # Replace default os.symlink with Windows specific code if running on Windows
    # Requires Administrator or Create Symlink permissions
    # See http://stackoverflow.com/a/28382515
    if platform == "windows":
        def symlink_ms(source, link_name):
            import ctypes
            csl = ctypes.windll.kernel32.CreateSymbolicLinkW
            csl.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
            csl.restype = ctypes.c_ubyte
            flags = 1 if os.path.isdir(source) else 0
            try:
                if csl(link_name, source.replace('/', '\\'), flags) == 0:
                    raise ctypes.WinError()
            finally:
                pass

        os.symlink = symlink_ms

    # Start development server on all IPs and using configured port
    try:
        run(host='0.0.0.0', port=PORT, debug=True)
    finally:
        with open('vmInventory', 'w') as f:
            json.dump(names, f)
            f.close()


if __name__ == '__main__':
    main()
