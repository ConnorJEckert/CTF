import socketio
import time

sio = socketio.Client()

@sio.event
def connect():
    print("[socket.io] connected")
    sio.emit("get_initial_data")

@sio.on("reactor_update")
def on_update(data):
    core = data.get("reactorCore", {})
    print(f"temp={core.get('coreTemperature_C')} pressure={core.get('corePressure_MPa')} "
          f"fuelTemp={core.get('fuelRods',{}).get('averageTemperature_C')} "
          f"rods={core.get('controlRods',{}).get('insertedPercentage')} "
          f"status={data.get('reactorStatus')}")
    if data.get("flag"):
        print("!!!!! FLAG FOUND:", data["flag"])
        sio.disconnect()

sio.connect("http://154.57.164.78:32086")
sio.wait()
