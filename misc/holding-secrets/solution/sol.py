from pyModbusTCP.client import ModbusClient
import time
client = ModbusClient('127.0.0.1')

regs_l = client.read_holding_registers(1024,reg_nb=35)
flag = ''.join(chr(i) for i in regs_l)
print(flag)

