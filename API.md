# tcpproxy.py / mallory revisited


# Plugin API

The plugin API has been kept as simple as possible, however, this required some consessions:

* Origin tcpproxy plugins should still work with the new plugin API. They are comprised of the following:

class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        self.name = "Module name"

        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = __file__.rsplit('/', 1)[1].split('.')[0]

        self.description = "Module description"


    def help(self):
        h = '\tfind: string that should be highlighted\n'
        h += ('\tcolor: ANSI color code. Will be wrapped with \\033[ and m, so'
              ' passing 32;1 will result in \\033[32;1m (bright green)')
        return h

    # This method is required.
    # It takes original data in input, must return potentially modified data
    def execute(self, data):
        return data

* The following optional tcpproxy plugin API method have been added to play with tunneled trafic (eg: SSL). This way SSL tunnelling will be handled in plugins instead of the tcpproxy engine.

    # This method is optional.
    # It is only used to retrieve the ConnData helper object
    def set_connection(self, conn_obj):
        self.conn = conn_obj

    # This method is optional.
    # It takes peeked data as input (first 1024 bytes only)
    # It must return a dict containing informative data if
    # something has been observed during peek
    def peek(self, data):
        return { "hello": "I found nothing" }

    # This method is optional.
    # It should be used with care as it will probably break
    # the connection is badly implemented
    # It takes as input a tuple of three socket (remote, local, and the socket to be wrapped)
    # The output must be a dict that could contains any of the following key
    # "remote_socket": the wrapped remote_socket that will replace the original socket
    # "local_socket" : the wrapped local_socket that will replace the original socket
    # "error" : an error message that will be sent to the debugger for user feedback
    # no action will be taken and current sockets will be used as it is
    def wrap(self, sock):
        remote_socket, local_socket, sock = sock

        return { "error" : "I won't wrap any socket"}

* Data storage in the class: data can be stored inside the plugin instance (the plugin is not destroyed while the connection is alive).

Please note however that two plugin instances are created for each connection: an inbound and outbound plugin (see the incoming parameter in __init__) and these instances won't share their data together.

This data can be seen as local plugin data.

* ConnData helper object: this object is shared between all plugin instance (inbound or outbound) of a given connection.

If possible only methods should be used on ConnData and no direct access class variables should be performed. Especially, it is advised not to store any variable inside this object.

This object is currently threadsafe as plugins are called sequentially, however in the future, it could be a problem and all methods will need to be implemented as thead safe methods.

Currently, this advice is only to avoid that plugins are screwing with each other by using or modifying the same variables.

The following methods are available on the ConnData objects:

  * get_channel(): return a string representing the connection that can be used for redis communication (prepended with the topic)

  * get_short_hash(): similar than get_channel but ignore the source port in order to represent a conversation between a client and server as a single event, even if there are multiple tcp connection.

  * get_dict(data=None, **kwargs): return a dict containing all the connection information + data encoded in base64 if provided. Also add any provided key/value arguments to the dict.

  * get_json(data=None, **kwargs): same as get_dict but retrieve directly a json string. Obviously to communicate directly with json brokers.

  * set_hostname(hostname): associate a server hostname to the connection

  * get_hostname(): get the hostname currently associated to the connection

  * add_tag(tag): assign an arbitrary tag to the connection

  * get_tags(): get the current tags assigned to the connection 

# Common Client / Server API

A Client / Server API has been defined using a redis json broker. Part of the API is based on a key/value store, but other functionnalities are defined using a pubsub as described below:

Note that redis API will be initialized only if tcpproxy is started with the --redis option

* rules: a list containing all rules.

These rules are only defined by the client. tcpproxy will read this rules for each connection initialization in order to instanciate all required modules.

A rule is constructed as following:
  { "dstport": int, "srcport": int, "hostname": regexp, "rules": [ "module1", "module2" ], "c2s": bool, "s2c": bool }

* modules: a list of modules supported by the tcpproxy engine

This list of module is created by the tcpproxy engine by reading python files available in ./proxymodule. If tcpproxy is started out of its root directory, this list will consequently not be populated.

ex: "stats debug"

* default_modules: a list of recommended modules that could be set by default

This list of module is created by the tcpproxy engine

ex: "stats"

# Plugins Client / Server API

Any plugin could use redis to communicate with the tcpproxy debugger UI. Here is an exemple of redis channels that are used by plugins:

* stats: the stats plugin aggregate statistics of connection into redis. These statistics should only be read by UI clients. The following keys are used:

stats:summary:bytes : short_hash
stats:summary:packets : short_hash
stats:connections:bytes : channel
stats:connections:packets : channel
stats:connections:status : channel

Client UI Usage example in python (r is the redis instance):
    for key, stat in r.hscan_iter("stats:summary:bytes"):
        data = key.split(":")
        print_packet({"src":data[0],"dst":data[1],"dstport":data[2],"hostname":data[3],"bytes":stat,"packets":r.hget("stats:summary:packets",key),"tags":data[4]})

    for key, stat in r.hscan_iter("stats:connections:bytes"):
        data = key.split(":")
        print_packet({"src":data[0],"srcport":data[1],"dst":data[2],"dstport":data[3],"hostname":data[4],"bytes":stat,"packets":r.hget("stats:connections:packets",key),"tags":data[5]})

* debug: the debug plugin sends packet details to redis in json. it basically uses ConnData.get_dict and sned the data to the redis channel pubsub for the connection.

debug:channel : received packet details in json

Client UI Usage exemple in python
pdebug = r.pubsub()
pdebug.psubscribe("debug:*")

while True:
    remain=True
    while remain:
        msg = pdebug.get_message()
        if msg and "data" in msg and not isinstance(msg["data"],long):
            packet_details = json.loads(msg["data"])
            data = base64.b64decode(packet_details["data"])
        else:
            remain=False

* inspect: the inspect plugin allow to interactively inspect packet. it sends packets details to redis in a json pubsub and wait for getting a packet back.

debugging: 1 to block packets for editions, 0 to forward packets. This setting should be set by the redis client and is read by the tcpproxy engine (default 0)
inspect:channel : received packet details in json in the format defined below
inspected:channel: packet details in json sent back from the Client UI (the data is eventually modified)
{ "src": ip, "dst": ip, "srcport": int, "dstport": int, "hostname": "unknown if no hostname is set", "data": base64string, "seq": int}

Client UI Usage exemple in python

pinspect = r.pubsub()
pinspect.psubscribe("inspect:*")

r.set("debugging",1)
while True:
    remain = True
    while remain:
        # Get message from redis queue
        msg = pinspect.get_message()
        if msg and "data" in msg and not isinstance(msg["data"],long):
            # Decode json object
            packet_details = json.loads(msg["data"])
            # Decode data as base64
            data = base64.b64decode(packet_details["data"])

            # Split channel to known connection details (the same data is present in the packet_details objects)
            channel = msg["channel"].split(":")
            print_packet({"src":channel[0],"srcport":channel[1],"dst":channel[2],"dstport":channel[3],"hostname":channel[4],"tags":channel[5]})

            if user_want_to_edit():
                # Edit the data using a hex editor, and send it to the channel inspected:*
                call_hexeditor(data)
                channel[0] = "inspected"
                channel = ":".join(channel)
                packet_details["data"] = base64.b64encode(data)
                r.publish(channel, json.dumps(json_obj))
            else:
                r.publish(channel, msg["data"])
        else:
            remain=False

r.set("debugging",0)

* ssl_upgrade: this module allow upgrading a connection to SSL. It can take multiple configuration options

All keys below can be read or written either by the tcpproxy engine or the UI interface. The tcpproxy engine will in general avoid replacing a key that already exists (so that the UI client has precedence).

ca:key : the PEM encoded assymetric key that will be used for any certificate signature. Will be generated on the first SSL request if it does not already exists.
ca:cert : the PEM encoded CA certificate that will be used to sign other certificates. Will be generated on the first SSL request if it does not already exists.

CN:cert: the PEM encoded certificate for a given server (CN). Either generated and cached by the tcpproxy plugin or manually set from UI client side.
CN:key : The assymetric key matching the PEM encoded certificate. If not provided from UI client side, the ca:key is used (generating a key is time consuming so we reuse the same key)
