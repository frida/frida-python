import frida


def main():
    device = frida.get_device_manager().add_remote_device("::1",
                                                          certificate="/Users/oleavr/src/cert.pem",
                                                          token="knock-knock")

    bus = device.get_bus()
    bus.on('message', on_bus_message)

    while True:
        message = input("> ").strip()

        if len(message) == 0:
            print("Processes:", device.enumerate_processes())
            continue

        bus.post({
            'type': 'chat',
            'text': message
        })


def on_bus_message(message, data):
    if message['type'] == 'chat':
        print("<{}> {}".format(message['sender'], message['text']))
    else:
        print("Unhandled message:", message)


if __name__ == '__main__':
    main()
