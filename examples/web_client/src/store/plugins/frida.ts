import { Plugin } from 'vuex';

import dbus from 'dbus-next';
import websocket from 'websocket-stream';

async function start() {
  const ws = websocket(`ws://${location.host}/ws`);
  const bus = dbus.peerBus(ws, {
    authMethods: ['ANONYMOUS'],
  });

  const hostSessionObj = await bus.getProxyObject('re.frida.HostSession14', '/re/frida/HostSession');
  const hostSession = hostSessionObj.getInterface('re.frida.HostSession14');

  const processes = await hostSession.EnumerateProcesses();
  console.log('Got processes:', processes);
}

export default function createFridaBusPlugin(): Plugin<any> {
  return (store: any) => {
    start().catch(e => {
      console.error(e);
    });
  };
}