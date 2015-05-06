#!/usr/bin/python

DOCUMENTATION='''
module: ssh_config
short_description: Configure SSH clients
description: >
  Except for `name`, all other options directly correspond to camel-cased Host options 
  described at ssh_config manpage. Note that, this module provides only minimal validation 
  of input values supplied to it.
options:
  name:
    description: Name this host stanza
    required: yes
  hostname:
    description: HostName
    required: no
  port: 
    description: Port
    required: no
  identity_file:
    description: IdentityFile
    required: no
  user:
    description: User
    required: no
  preferred_authentications:
    description: PreferredAuthentications
    required: no
    default: 'publickey,password'
  proxy_command:
    description: ProxyCommand
    required: no
  tunnel:
    description: Tunnel
    required: no
  local_forward:
    description: LocalForward
    required: no
  remote_forward:  
    description: RemoteForward
    required: no
  hash_known_hosts:
    description: HashKnownHosts
    required: no
    choices: ['yes', 'no']
  host_key_alias:
    description: HostKeyAlias
    required: no
  send_env:
    description: SendEnv
    required: no
  request_tty:
    description: RequestTTY
    required: no
    choices: ['no', 'yes', 'force', 'auto']
  strict_host_key_checking:
    description: StrictHostKeyChecking
    required: no
    choices: ['yes', 'no', 'ask']
'''

EXAMPLES=r'''
- ssh_config:
    name: '*.example.com'
    user: root
    preferred_authentications: 
    - 'publickey'
    - 'password'
    identity_file: '~/.ssh/id_rsa-1'

- ssh_config:
    name: 'baz.example.com'
    user: baz
    port: 10222
    preferred_authentications: 'publickey'
    identity_file: '~/.ssh/id_rsa-2'
    local_forward: '5433 127.0.0.1:5432'

# Use opts to pass a whole dict
- ssh_config: 
    name: '{{item.name}}'
    opts: '{{item}}'
  with_items:
  - name: 'qaz.andara.com'
    hostname: 'andara.com'
    user: qaz
    port: 50022
    identity_file: '~/.ssh/id_rsa-5'
  - name: 'baz.andara.com'
    hostname: 'andara.com'
    user: baz
    port: 60022
    identity_file: '~/.ssh/id_rsa-6'
'''

import re
import os
from collections import OrderedDict
from tempfile import NamedTemporaryFile

from ansible.module_utils.basic import *

hacking = 'ANSIBLE_HACKING' in os.environ
ssh_config_file = '/var/tmp/ssh_config.1' if hacking else os.path.expanduser('~/.ssh/config')

def parse_config(config_lines):
    
    re_host = re.compile('^Host\s+')

    stanzas = OrderedDict()
    n0, host = 0, None
    for n, l in enumerate(config_lines):
        if re_host.match(l):
            if host:
               stanzas[host] = slice(n0, n)
            host = re_host.sub('', l).strip()
            n0 = n
    if host:
        stanzas[host] = slice(n0, n + 1)
    
    return stanzas

def generate_host_config(name, p):
    
    lines = [
        'Host %s\n' % (name),
    ]
    
    v = p.get('hostname')
    if v:
        lines.append('  HostName %s\n' % (v))
    
    v = p.get('user')
    if v:
        lines.append('  User %s\n' % (v))
    
    v = p.get('port')
    if v:
        lines.append('  Port %d\n' % (v)) 
    
    v = p.get('identity_file')
    if v:
        if os.access(os.path.expanduser(v), os.R_OK):
            lines.append('  IdentityFile %s\n' % (v))
        else:
            raise ValueError('The identity file %s is not accesible' % (v))

    allowed_authentications = set([
        'gssapi-with-mic', 'hostbased', 'publickey', 'keyboard-interactive', 'password'])
    v = p.get('preferred_authentications')
    if v:
        v = v.split(',') if isinstance(v, basestring) else v
        v1 = [x for x in v if x in allowed_authentications]
        lines.append('  PreferredAuthentications %s\n' % (','.join(v1)))
    
    v = p.get('proxy_command')
    if v:
        lines.append('  ProxyCommand %s\n' % (v))
    
    v = p.get('tunnel')
    if v:
        lines.append('  Tunnel %s\n' % (v))
    
    v = p.get('local_forward')
    if v:
        # Todo Validate <port> <host>:<port>
        lines.append('  LocalForward %s\n' % (v))
    
    v = p.get('remote_forward')
    if v:
        # Todo Validate <port> <host>:<port>
        lines.append('  RemoteForward %s\n' % (v))
    
    v = p.get('hash_known_hosts')
    if v is not None:
        lines.append('  HashKnownHosts %s\n' % ('yes' if v else 'no'))
    
    v = p.get('send_env')
    if v:
        lines.append('  SendEnv %s\n' % (v))
    
    v = p.get('request_tty')
    if v:
        lines.append('  RequestTTY %s\n' % (v))
    
    v = p.get('host_key_alias')
    if v:
        lines.append('  HostKeyAlias %s\n' % (v))
    
    v = p.get('strict_host_key_checking')
    if v:
        lines.append('  StrictHostKeyChecking %s\n' % (v))
    
    return lines

def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True),
            hostname = dict(),
            host_key_alias = dict(),
            hash_known_hosts = dict(choices=['yes', 'no']),
            port = dict(type='int'),
            identity_file = dict(),
            user = dict(),
            preferred_authentications = dict(),
            proxy_command = dict(),
            tunnel = dict(),
            local_forward = dict(),
            remote_forward = dict(),
            send_env = dict(),
            request_tty = dict(choices=['yes', 'no', 'force', 'auto']),
            strict_host_key_checking = dict(choices=['yes', 'no', 'ask']),
            # an alternative: pass all parameters as a dict
            opts = dict()
        )
    )
    
    name = module.params.get('name') or '*'
    
    if os.path.isfile(ssh_config_file):
        with open(ssh_config_file, 'r') as fp:
            config_data = fp.read()
        config_lines = config_data.splitlines(True)
    else:
        config_lines = []

    # Split to host stanzas
    
    stanzas = parse_config(config_lines)
    hosts = stanzas.keys()
    
    # Generate a new host stanza
    
    opts = module.params.get('opts') 
    p = opts if opts else module.params
    try:
        new_config_lines = generate_host_config(name, p)
    except ValueError as ex:
        module.fail_json(msg=ex.message)

    # Replace or append host-based option lines
    
    re_comment = re.compile('^\s*#')
    re_blank = re.compile('^\s*$')

    with NamedTemporaryFile(delete=False) as ofp:
        if name in hosts: # replace
            # Preserve initial comments
            r0 = stanzas[hosts[0]]
            ofp.writelines(config_lines[0:r0.start])
            # Print host stanzas
            for host in hosts:
                r = stanzas[host]
                if host == name:
                    ofp.writelines(new_config_lines)
                    # Preserve footer comments in this stanza, if any
                    is_comment = lambda l: re_comment.match(l) or re_blank.match(l)
                    i = next(j for j in reversed(range(r.start, r.stop))
                        if not is_comment(config_lines[j]))
                    ofp.writelines(config_lines[i+1:r.stop])
                else: 
                    ofp.writelines(config_lines[r])
        else: # append
           ofp.writelines(config_lines)
           ofp.write("\n")
           ofp.writelines(new_config_lines)
    
    # Update target file
    
    try:
        os.rename(ofp.name, ssh_config_file)
    except Exception as ex:
        module.fail_json(msg='Failed to rename target file')
    else:
        module.exit_json(changed=True, name=name, target_file=ssh_config_file, p=p)
        
# Go!
main()
