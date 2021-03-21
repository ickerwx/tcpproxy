#!/usr/bin/env python

import sys,json,re,argparse,base64,signal,hexdump

parser = argparse.ArgumentParser()

parser.add_argument("host", help="The target host running redis")
parser.add_argument("topic", help="List or do action on topic [certs,rules,convs,conns,all]", nargs="?", default="all")
parser.add_argument("-c", "--clear", action="store_true", help="Clear the topic")
parser.add_argument("-a", "--add", nargs="?", help="Add an item", type=int, const=-1)
parser.add_argument("-r", "--replace", help="Edit an item (id key value)", nargs="+")
parser.add_argument("-d", "--delete", help="Delete an item", type=int)
parser.add_argument("-l", "--level", help="Debug level", default="INFO")

import redis,json,re,base64,subprocess
class TCPProxyClient:

    def __init__(self, host):
        print ("Connecting to redis on host %s ..." % host)
        self.r = redis.StrictRedis(host=host)
        print ("Connected")

    def print_packet(self, msg, level="DEBUG"):
        for key,value in msg.items():
            if isinstance(value,bytes):
                msg[key] = value.decode("utf-8")
            elif isinstance(value,list):
                if isinstance(value[0],bytes):
                    msg[key] = b' '.join(value).decode("utf-8")
                else:
                    msg[key] = ' '.join(value)
            elif isinstance(value,bool):
                msg[key] = value.__str__()
            elif isinstance(value,int):
                msg[key] = str(value)

        toprint = [msg["src"]]
        if "srcport" in msg:
            toprint.append(msg["srcport"])
        toprint.extend([msg["dst"],msg["dstport"]])

        if "packets" in msg:
            toprint.append(msg["packets"])
        if "bytes" in msg:
            toprint.append(msg["bytes"])
        if "hostname" in msg:
            if msg["hostname"] == None:
                toprint.append("undefined")
            else:
                toprint.append(msg["hostname"])
        if "rules" in msg:
            toprint.extend([ msg["c2s"], msg["s2c"], msg["rules"] ])
        if "tags" in msg:
            toprint.append(msg["tags"])

        print('\t'.join(toprint))
        
        if "data" in msg:
            if "level" not in msg or msg["level"] == "DEBUG":
                hexdump.hexdump(base64.b64decode(msg["data"]))
            else:
                print(msg["level"]+":"+ base64.b64decode(msg["data"]).decode("utf-8"))

    def get_iter(self,chan):
        return self.r.hscan_iter(chan)

    def get_value(self,chan,key):
        return self.r.hget(chan,key)

    def clear_connections(self):
        self.clear_iter("stats:connections:packets")
        self.clear_iter("stats:connections:bytes")

    def clear_conversations(self):
        self.clear_iter("stats:summary:packets")
        self.clear_iter("stats:summary:bytes")

    def clear_iter(self,chan):
        for item,value in self.get_iter(chan):
            self.r.hdel(chan,item)

    def get_key(self, key):
        return self.r.get(key)
    
    def delete_key(self,  key):
        self.r.delete(key)
    
    def set_key(self, key, value):
        self.r.set(key, value)

    def get_key_iter(self, key):
        return self.r.keys(key)

    def get_rules(self):
        rules = self.get_key("rules")
        if rules:
            return json.loads(rules)
        else:
            return []

    def clear_rules(self):
        self.r.delete("rules")

    def get_certs(self):
        return self.get_key_iter("*:x509*")

    def get_modules(self):
        return self.get_key("modules").decode("utf-8")

    def get_suggested_modules(self):
        return self.get_key("default_modules").decode("utf-8")

    def get_modules_help(self):
        for m in self.get_key_iter("module:*:help"):
            yield (m.split(b":")[1], self.get_key(m).decode("utf-8"))

    def clear_certs(self):
        for cert in self.get_certs():
            self.r.delete(cert)

    def delete_rule(self, rule_number):
        rules = self.get_rules()
        del(rules[rule_number])
        self.save_rules(rules)

    def save_rules(self, rules):
        self.r.set("rules",json.dumps(rules))

    def add_rule(self, rule, pos=-1):
        rules = self.get_rules()
        if pos==-1:
            rules.append(rule)
        else:
            rules = rules[0:pos]+[rule]+rules[pos:]
        self.save_rules(rules)

    def edit_rule(self, pos, key, value):
        rules = self.get_rules()
        if key == "rules":
            value = value.split(" ")
        if value == "None":
            value = None
        rules[pos][key] = value
        self.save_rules(rules)

    def register_debug(self, key="*"):
        self.debug = self.r.pubsub()
        self.debug.psubscribe("debug:"+key)

    def debug_iter(self, timeout=0):
        msg = self.debug.get_message(timeout=timeout)
        if msg and "data" in msg and not isinstance(msg["data"],int):
            yield json.loads(msg["data"])

    def inspect_iter(self, timeout=0):
        msg = self.inspect.get_message(timeout=timeout)
        if msg and "data" in msg and not isinstance(msg["data"],int):
            yield json.loads(msg["data"])

    def register_inspect(self, key="*"):
        self.inspect = self.r.pubsub()
        self.inspect.psubscribe("inspect:"+key)
        self.enable_interception()

    def commit_inspected_msg(self, msg):
        channel = ":".join(["inspected",msg["src"],str(msg["srcport"]),msg["dst"],str(msg["dstport"])])
        print("Will publish inspected data to channel %s" % channel)
        self.r.publish(channel, json.dumps(msg))

    def enable_interception(self):
        self.r.set("debugging",1)

    def disable_interception(self):
        self.r.set("debugging",0)
        
    def toggle_interception(self):
        if is_intercepting():
            self.disable_interception()
        else:
            self.enable_interception()
            
    def is_intercepting(self):
        return self.r.get("debugging") == 1

    def parse_key(self, key):
        key = key.split(b":")
        data = {"src": key[0]}
        if len(key) < 6:
            key = key[1:]
        else:
            data["srcport"] = key[1]
            key = key[2:]
        data.update({
            "dst": key[0],
            "dstport": key[1],
            "hostname": key[2],
            "tags": key[3].split(b",")
        })

        return data

    def print_stats(self, chan):
        for key, bytes in self.get_iter(chan+":bytes"):
            data = self.parse_key(key)
            data["bytes"] = bytes
            data["packets"] = self.get_value(chan+":packets", key)
            self.print_packet(data)

    def get_stats(self, chan):
        stats = []
        for key, bytes in self.get_iter(chan+":bytes"):
            data = self.parse_key(key)
            data["bytes"] = bytes
            data["packets"] = self.get_value(chan+":packets", key)
            stats.append(data)
        return stats

    def print_conversations(self):
        # Print Headers
        print ("Conversations:")
        self.print_packet({
            "src":b"Source\t",
            "dst":b"Destination",
            "dstport":b"Port",
            "packets":b"Packets",
            "bytes":b"Bytes",
            "hostname":b"Hostname",
            "tags":[b"Tags"]
        })

        self.print_stats("stats:summary")

    def print_connections(self):
        # Print Headers
        print ("Connections:")
        self.print_packet({
            "src":b"Source\t",
            "srcport":b"Port",
            "dst":b"Destination",
            "dstport":b"Port",
            "packets":b"Packets",
            "bytes":b"Bytes",
            "hostname":b"Hostname",
            "tags":[b"Tags"]
        })
        
        self.print_stats("stats:connections")

    def print_rules(self):
        print ("Current Rules:")
        self.print_packet({
            "src":b"Source\t",
            "dst":b"Dest",
            "hostname":b"Hostname",
            "dstport":b"Port",
            "c2s":b"c2s",
            "s2c":b"s2c",
            "rules":["Rules"]
        })

        for rule in self.get_rules():
            self.print_packet(rule)

    def print_certs(self):
        print ("Certificates")
        for cert in self.get_certs():
            print ("%s:" % cert.decode("utf-8"))
            cmd = subprocess.Popen(["openssl","x509","-text"], stdin=subprocess.PIPE)
            cmd.communicate(self.get_key(cert))

    def print_modules(self):
        print ("Available modules:")
        print (self.get_modules())
        for m,mhelp in self.get_modules_help():
            print("%s: %s" % (m.decode("utf-8"),mhelp))
        print ("Suggested modules:")
        print (self.get_suggested_modules())

def add_rule(default_rule):
    src = input("Source IP (default: .*):")
    if not src.strip():
        src = ".*"
    dst = input("Destination IP (default: .*):")
    if not dst.strip():
        dst = ".*"
    hostname = input("Destination hostname (default: None):")
    if not hostname.strip():
        hostname = None
    dstport = input("Destination port range (default: 0-65535):")
    if not dstport.strip():
        dstport = "0-65535"
    direction = input("Direction (c2s,s2c,both) (default: both):")
    if not direction.strip():
        direction = "both"

    rule = input("Rules (none for default plugins):")
    if rule:
        rule = rule.split(" ")
    else:
        rule = default_rule.split(" ")

    rule = { "src":src, "dst":dst, "dstport":dstport, "rules":rule, "c2s": direction in [ "c2s", "both" ], "s2c": direction in [ "s2c", "both" ], "hostname": hostname }
    return rule

if __name__ == '__main__':
    args = parser.parse_args()

    client = TCPProxyClient(args.host)

    if args.topic in ["certs", "all"]:
        if args.clear:
            print ("Clearing up certs")
            client.clear_certs()
        else:
            client.print_certs()
    if args.topic in ["rules", "all"]:
        if args.clear:
            print ("Clearing up rules")
            client.clear_rules()
        elif args.delete:
            client.delete_rule(args.delete)
        elif args.replace:
            id,key,value = args.replace
            client.edit_rule(int(id), key, value)
        elif args.add:
            client.print_modules()
            rule = add_rule(client.get_suggested_modules())
            client.add_rule(rule,args.add)

        client.print_rules()
    if args.topic in ["convs", "all"]:
        if args.clear:
            print ("Clearing up conversations statistics")
            client.clear_conversations()
        else:
            client.print_conversations()
    if args.topic in ["conns", "all"]:
        if args.clear:
            print ("Clearing up connections statistics")
            client.clear_connections()
        else:
            client.print_connections()
    if args.topic in ["debug","inspect","all"]:

        def signal_handler(sig, frame):
            print ("Ctrl+C Pressed!")
            print ("Detaching debugger")
            client.disable_interception()
            sys.exit(0)

        def signal_handler_simple(sig, frame):
            print ("Ctrl+C Pressed!")
            sys.exit(0)

        if args.topic in ["debug", "all"]:
            print ("Showing debugged packets")
            client.register_debug()

        if args.topic in ["inspect", "all"]:
            print ("Showing inspected packets")
            signal.signal(signal.SIGINT, signal_handler)
            client.register_inspect()
        else:
            signal.signal(signal.SIGINT, signal_handler_simple)

        while True:
            if args.topic in ["debug", "all"]:
                for msg in client.debug_iter():
                    client.print_packet(msg)

            if args.topic in ["inspect", "all"]:
                for msg in client.inspect_iter():
                    client.print_packet(msg)
