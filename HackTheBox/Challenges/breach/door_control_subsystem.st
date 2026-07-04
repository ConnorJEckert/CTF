// Configuration notes:
// 8-bit word size
// Modify Modbus coil access to restrict door coils
PROGRAM door_control
  VAR
    system_active AT %QX75.2 : BOOL := 0;
  END_VAR
  VAR
    Door_0 AT %Q4.0 : BOOL := 0; // Restrict write access via Modbus
    Door_1 AT %Q4.1 : BOOL := 0; // Restrict write access via Modbus
    Door_2 AT %Q4.2 : BOOL := 0; // Restrict write access via Modbus
    Door_3 AT %Q4.3 : BOOL := 0; // Restrict write access via Modbus
    Door_4 AT %Q4.4 : BOOL := 0; // Restrict write access via Modbus
    sensor_0 AT %QX8.0 : BOOL := 0;
    sensor_1 AT %QX8.1 : BOOL := 0;
    sensor_2 AT %QX8.2 : BOOL := 0;
    sensor_3 AT %QX8.3 : BOOL := 0;
    sensor_4 AT %QX8.4 : BOOL := 0;
    sensor_5 AT %QX37.0 : BOOL := 0;
    sensor_6 AT %QX37.1 : BOOL := 0;
    sensor_7 AT %QX37.2 : BOOL := 0;
    sensor_8 AT %QX37.3 : BOOL := 0;
    sensor_9 AT %QX37.4 : BOOL := 0;
    sensor_10 AT %QX52.0 : BOOL := 0;
    sensor_11 AT %QX52.6 : BOOL := 0;
    sensor_12 AT %QX16.6 : BOOL := 0;
    sensor_13 AT %QX16.7 : BOOL := 0;
    sensor_14 AT %QX16.0 : BOOL := 0;
  END_VAR
  VAR
    TON0 : TON;
  END_VAR
  VAR_TEMP
    door_timer_0 : TIME;
    door_timer_1 : TIME;
    door_timer_2 : TIME;
    door_timer_3 : TIME;
    door_timer_4 : TIME;
  END_VAR
  VAR
    TON1 : TON;
    TON2 : TON;
    TON3 : TON;
    TON4 : TON;
  END_VAR

  TON0(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_1) AND sensor_4 AND NOT(sensor_2) AND sensor_1 AND sensor_0 AND system_active, PT := T#8000ms);
  Door_0 := TON0.Q;
  door_timer_0 := TON0.ET;
  TON1(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_0) AND sensor_7 AND NOT(sensor_6) AND sensor_5 AND sensor_0 AND system_active, PT := T#5000ms);
  Door_1 := TON1.Q;
  door_timer_1 := TON1.ET;
  TON2(IN := NOT(Door_4) AND NOT(Door_3) AND NOT(Door_1) AND NOT(Door_0) AND sensor_11 AND NOT(sensor_7) AND sensor_10 AND sensor_5 AND system_active, PT := T#8000ms);
  Door_2 := TON2.Q;
  door_timer_2 := TON2.ET;
  TON3(IN := NOT(Door_4) AND NOT(Door_1) AND NOT(Door_2) AND NOT(Door_0) AND sensor_13 AND sensor_12 AND NOT(sensor_11) AND sensor_10 AND system_active, PT := T#5000ms);
  Door_3 := TON3.Q;
  door_timer_3 := TON3.ET;
  TON4(IN := NOT(Door_1) AND NOT(Door_3) AND NOT(Door_2) AND NOT(Door_0) AND sensor_14 AND sensor_13 AND sensor_12 AND sensor_10 AND system_active, PT := T#8000ms);
  Door_4 := TON4.Q;
  door_timer_4 := TON4.ET;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#1000ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : door_control;
  END_RESOURCE
END_CONFIGURATION
