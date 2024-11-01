#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SP2ONG 2024 SVXLink Remote LCD2004 Monitor
# na bazie kodu oledsvx SP2AM 2024
#
# Working with ESP32/Wemos-D1+ESPEasy+LCD
#
# options in remotelcd.ini
#
# Offset temperatury CPU dla OZPI V1 LTS wynosi 30 
# dla innych komputerow SBC  ustawic 0
temp_offset = 0

import subprocess
import argparse
import configparser
import glob
import json
import logging
import os
import psutil
import re
import signal
import socket
import sys
import threading
import time
import requests
from requests.exceptions import HTTPError
from unidecode import unidecode

from datetime import datetime, timedelta
from json.decoder import JSONDecodeError

from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def welcome_msg():
  global ip_address
  payload = {'cmd':'event,Data1="     FM  POLAND     ","   N E T W O R K  "'}
  try:
      response = requests.get('http://'+ip_address+'/control', params=payload, timeout=5)
      response.raise_for_status()
      if response:
         logger.debug(f"Send welcome message")
  except requests.exceptions.HTTPError as errh:
      logger.debug(f"Http Error:",errh)
  except requests.exceptions.ConnectionError as errc:
      logger.debug(f"Error Connecting:",errc)
  except requests.exceptions.Timeout as errt:
      logger.debug(f"Timeout Error:",errt)
  except requests.exceptions.RequestException as err:
      logger.debug(f"OOps: Something Else",err)

def shutdown_msg():
  global ip_address
  payload1 = {'cmd':'event,Data1="   Remote  Display  ","   S h u t d o w n  "'}
  payload2 = {'cmd':'LCDcmd,off'}
  payload3 = {'cmd':'LCDcmd,clear'}
  try:
      response = requests.get('http://'+ip_address+'/control', params=payload1, timeout=5)
      time.sleep(5)
      response = requests.get('http://'+ip_address+'/control', params=payload2, timeout=5)
      time.sleep(0.5)
      response = requests.get('http://'+ip_address+'/control', params=payload3, timeout=5)
      response.raise_for_status()
      if response:
         logger.debug(f"Send shutdown message")
  except requests.exceptions.HTTPError as errh:
      logger.debug(f"Http Error:",errh)
  except requests.exceptions.ConnectionError as errc:
      logger.debug(f"Error Connecting:",errc)
  except requests.exceptions.Timeout as errt:
      logger.debug(f"Timeout Error:",errt)
  except requests.exceptions.RequestException as err:
      logger.debug(f"OOps: Something Else",err)

def status1_ip_msg(ipa,cl,tc,tga,refs):
  global ip_address
  ipad = "IP "+str(ipa)
  status = "CPU: "+str(cl)+"%  TEMP: "+str(tc)+"{D}C"
  payload = {'cmd':'event,Data2="'+str(status)+'","'+f'{ipad:^20}'+'","'+f'{unidecode(tga):^20}'+'","'+str(refs)+'"'}
  try:
      response = requests.get('http://'+ip_address+'/control', params=payload, timeout=5)
      response.raise_for_status()
      if response:
         logger.debug(f"Send IP address and status message - cpu load and temperature, ATG")
  except requests.exceptions.HTTPError as errh:
      logger.debug(f"Http Error:",errh)
  except requests.exceptions.ConnectionError as errc:
      logger.debug(f"Error Connecting:",errc)
  except requests.exceptions.Timeout as errt:
      logger.debug(f"Timeout Error:",errt)
  except requests.exceptions.RequestException as err:
      logger.debug(f"OOps: Something Else",err)

def status2_ip_msg(ipa,cl,tc,th,tga,refs):
  global ip_address
  ipad = "IP "+str(ipa)
  status = "CPU:"+str(cl)+"% TEMP:"+str(tc)+"|"+str(th)+"{D}C"
  payload = {'cmd':'event,Data2="'+str(status)+'","'+f'{ipad:^20}'+'","'+f'{unidecode(tga):^20}'+'","'+str(refs)+'"'}
  try:
      response = requests.get('http://'+ip_address+'/control', params=payload, timeout=5)
      response.raise_for_status()
      if response:
         logger.debug(f"Send IP address and status message - cpu load, temp and DS18B20, ATG, REF Stat")
  except requests.exceptions.HTTPError as errh:
      logger.debug(f"Http Error:",errh)
  except requests.exceptions.ConnectionError as errc:
      logger.debug(f"Error Connecting:",errc)
  except requests.exceptions.Timeout as errt:
      logger.debug(f"Timeout Error:",errt)
  except requests.exceptions.RequestException as err:
      logger.debug(f"OOps: Something Else",err)

def talker_msg(tgnr,call,tgname,refs):
  global ip_address
  tgn = "TG "+str(tgnr)
  payload = {'cmd':'event,Data2="'+f'{str(call):^20}'+'","'+f'{str(tgn):^20}'+'","'+f'{unidecode(tgname):^20}'+'","'+str(refs)+'"'}
  try:
      response = requests.get('http://'+ip_address+'/control', params=payload, timeout=5)
      response.raise_for_status()
      if response:
         logger.debug(f"Send Talker info ")
  except requests.exceptions.HTTPError as errh:
      logger.debug(f"Http Error:",errh)
  except requests.exceptions.ConnectionError as errc:
      logger.debug(f"Error Connecting:",errc)
  except requests.exceptions.Timeout as errt:
      logger.debug(f"Timeout Error:",errt)
  except requests.exceptions.RequestException as err:
      logger.debug(f"OOps: Something Else",err)

def backlight_off():
  global ip_address
  payload = {'cmd':'LCDCMD,off'}
  try:
      response = requests.get('http://'+ip_address+'/control', params=payload, timeout=5)
      response.raise_for_status()
      if response:
         logger.debug(f"Send contral low value ")
  except requests.exceptions.HTTPError as errh:
      logger.debug(f"Http Error:",errh)
  except requests.exceptions.ConnectionError as errc:
      logger.debug(f"Error Connecting:",errc)
  except requests.exceptions.Timeout as errt:
      logger.debug(f"Timeout Error:",errt)
  except requests.exceptions.RequestException as err:
      logger.debug(f"OOps: Something Else",err)

def backlight_on():
  global ip_address
  payload = {'cmd':'LCDCMD,on'}
  try:
      response = requests.get('http://'+ip_address+'/control', params=payload, timeout=5)
      response.raise_for_status()
      if response:
         logger.debug(f"Send contral normal value ")
  except requests.exceptions.HTTPError as errh:
      logger.debug(f"Http Error:",errh)
  except requests.exceptions.ConnectionError as errc:
      logger.debug(f"Error Connecting:",errc)
  except requests.exceptions.Timeout as errt:
      logger.debug(f"Timeout Error:",errt)
  except requests.exceptions.RequestException as err:
      logger.debug(f"OOps: Something Else",err)

def shutdown_signal_handler(signum, frame):
    global shutdown
    shutdown = True

class Call:
    def __init__(self, caller, tgnum, tgname, state, entrytime):
        self.caller = caller
        self.tgnum = tgnum
        self.tgname = tgname
        self.entrytime = entrytime
        allowed_states = [ 'start', 'stop' ]
        if state not in allowed_states:
            raise Exception("Call() with unknown state '%s'. Supported states: %s." % (state, ", ".join(allowed_states)))
        self.state = state

    def __str__(self):
        return f"Caller: {self.caller}, TG Number: {self.tgnum}, TG Name: {self.tgname}, State: {self.state}, Entry time: {self.entrytime}"

    def __repr__(self):
        return self.__str__()

class SvxLogMonitor:
    class EventHandler(FileSystemEventHandler):
        def __init__(self, monitor):
            super().__init__()
            self.monitor = monitor

        def on_modified(self, event):
            if event.src_path != self.monitor.logfile:
                return

            logger.debug(f"EventHandler: on modified event: {event}")
            self.monitor.process()

        def on_created(self, event):
            if event.src_path != self.monitor.logfile:
                return

            logger.debug(f"EventHandler: on created event: {event}")
            self.monitor.reopen()

        def on_moved(self, event):
            if event.dest_path != self.monitor.logfile:
                return

            logger.debug(f"EventHandler: on moved event: {event}")
            self.monitor.reopen()

    def __init__(self, screen, logfile="/var/log/svxlink"):
        self.screen = screen
        self.logfile = logfile
        self.re_talker =  re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<msecs>\d{3}))?: ReflectorLogic: Talker (?P<state>(start|stop)) on TG #(?P<tgnum>\d+): (?P<caller>.*)')
        self.re_tg_current =  re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<msecs>\d{3}))?: ReflectorLogic: Selecting TG #(?P<tgnum>\d+)')
        self.re_start = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<msecs>\d{3}))?: Starting logic:')
        self.re_disconnected = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<msecs>\d{3}))?: ReflectorLogic: Disconnected from')
        self.re_connected = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<msecs>\d{3}))?: ReflectorLogic: Connection established')
        self.re_shutdown = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<msecs>\d{3}))?: .* Shutting down application')
        self.re_node_activity = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(?P<msecs>\d{3}))?: ReflectorLogic: Node (joined|left)')

        self.buffer = ""

        self.open(notifier=False)
        self.initial_process()

        self.event_handler = self.EventHandler(self)
        self.observer = Observer()
        self.observer.schedule(self.event_handler, "/var/log", recursive=False)
        self.observer.start()

    def initial_process(self):
        # speed up by processing only last 5kB
        size_back = 5*1024

        self.fh.seek(0, 2)
        file_size = self.fh.tell()
        if file_size > size_back:
            self.fh.seek(file_size-size_back)
        else:
            self.fh.seek(0)

        # process to find out current tg group
        self.process()
        last_tg_current_call = None
        for call in self.screen.calls:
            if call.tgnum == self.screen.current_tg:
                last_tg_current_call = call
        # leave only last entry for a group
        if last_tg_current_call:
            self.screen.calls = [ last_tg_current_call ]

    def open(self, notifier=True):
        self.fh = open(self.logfile, 'r', encoding='utf-8')

    def close(self):
        self.fh.close()

    def reopen(self):
        logger.debug("SvxLogMonitor: reopening svxlink log file")
        self.close()
        self.open()

    def stop_monitoring(self):
        self.observer.stop()
        self.observer.join()

    def process(self):
        logger.debug(f"SvxLogMonitor process called")
        self.buffer += self.fh.read()
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)

            m = self.re_talker.match(line)
            if m:
                logger.debug(f"SvxLogMonitor process: matched talker line {line}")
                date = m.group('date')
                msecs = m.group('msecs')
                # handle format with and without microseconds
                if msecs is None:
                    date += ".000"
                else:
                    date += ".%03d" % int(msecs)
                state = m.group('state')
                tgnum = int(m.group('tgnum'))
                tgname = self.screen.get_tgname(tgnum)
                caller = m.group('caller')

                entrytime = datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')

                self.screen.calls.append(Call(tgnum=tgnum, tgname=tgname, state=state, entrytime=entrytime, caller=caller))
                continue

            m = self.re_tg_current.match(line)
            if m:
                logger.debug(f"SvxLogMonitor process: matched current tg group line {line}")
                self.screen.current_tg = int(m.group('tgnum'))
                continue

            if self.re_node_activity.match(line):
                logger.debug(f"SvxLogMonitor process: matched node activity line {line}")
                # for node activity we don't zeroe calls
                self.screen.reflector_connected(clean_calls=False)
                continue

            if self.re_connected.match(line):
                logger.debug(f"SvxLogMonitor process: matched connected line {line}")
                self.screen.reflector_connected()
                continue

            if self.re_disconnected.match(line) or self.re_shutdown.match(line):
                logger.debug(f"SvxLogMonitor process: matched disconnected / shutdown line {line}")
                self.screen.reflector_disconnected()
                continue

            if self.re_start.match(line):
                logger.debug(f"SvxLogMonitor process: matched start line {line}")

                # initialize to default state
                self.screen.init_calls()
                continue

class Screen:
    def __init__(self, ip_address="127.0.0.1",ext_temp_sensor=False):

        self.ext_temp_sensor = ext_temp_sensor

        self.backlight_time = backlight_time
        self.backlight_locked = False
        self.backlightoff_status = False
        self.backlighton()

        self.init_calls()

        self.tg_names = {}
        self.tg_names_update_time = 0

        self.reflector_connected_flag = False
        self.show_last = False

        self.backlight_lock()

    def backlighton(self):
        if self.backlight_locked:
            return
        backlight_on()
        self.backlightoff_status = False

    def backlightoff(self):
        if self.backlight_locked:
            return
        if not self.backlightoff_status:
           backlight_off()
           self.backlightoff_status = True

    def backlight_lock(self):
        self.backlight_locked = datetime.now()

    def check_backlight_lock(self):
        if self.backlight_locked:
            tdiff = datetime.now() - self.backlight_locked
            if tdiff > timedelta(minutes=self.backlight_time) and self.backlight_time != 0:
                self.backlight_locked = False

    def reflector_connected(self, clean_calls=True):
        self.reflector_connected_flag = True

        if clean_calls:
            # initialize to default state
            self.show_last = False
            self.init_calls()

    def reflector_disconnected(self):
        self.reflector_connected_flag = False
        self.show_last = False

        # initialize to default state
        self.init_calls()

    def init_calls(self):
        self.calls = []
        self.current_call = Call(caller=None, tgnum=0, tgname=None, state='stop', entrytime = datetime.now())
        self.current_tg = 0

    def __update_tgnames(self):
        tgfile = Path("/var/www/html/include/tgdb.json")
        if tgfile.exists():
            try:
                tgmtime = tgfile.stat().st_mtime
                if tgmtime > self.tg_names_update_time:
                    with tgfile.open(encoding='utf-8') as f:
                        self.tg_names = json.load(f)
                        self.tg_names_update_time = tgmtime
            except JSONDecodeError as e:
                pass

    def get_tgname(self, tg):
        tg = int(tg)
        if tg == 0:
            return "Brak aktywnej grupy"
        if tg >= 26099900:
            return "AUTO QSY"
        self.__update_tgnames()
        if str(tg) in self.tg_names:
            tgn = re.sub(r'[^a-zA-Z0-9ążźśćęńłóĄŻŹŚĆĘŃŁÓ:,\-\s]',"",self.tg_names[str(tg)])
            # limit characters
            return str(tgn)[:17]
        return "Nieznana"

    def __update_status(self):
        self.backlightoff()
        tga = self.__update_tg()
        current_second = int(time.time()) % 10
        if current_second in range(1):
            ipa = self.__update_ip()
            clth = self.update_temp_and_load()
            refs = self.__update_reflector_connected_stat()
            if len(clth) == 2:
                status1_ip_msg(ipa,clth[0],clth[1],tga,refs)
            else:
                status2_ip_msg(ipa,clth[0],clth[1],clth[2],tga,refs)

    def __update_talker(self, call):
        self.backlighton()
        if self.backlight_locked == False and len(self.calls):
            backlight_on()
        refs = self.__update_reflector_connected_stat()
        talker_msg(str(call.tgnum),call.caller, call.tgname, refs)

    def __update_reflector_connected_stat(self):
        self.svxlink_alive()
        if self.reflector_connected_flag:
            # connection to reflector status
             #return f'{"SVXRef UP":>14}'
             return "Ref:C"
        else:
             return "Ref:D"

    def update_talkers_or_status(self):
        talker_shown = False
        if self.calls and len(self.calls):
            while self.calls:
                call = self.calls.pop(0)
                if self.current_tg == 0 or call.tgnum == self.current_tg:
                    self.__update_talker(call)
                    talker_shown = True
                    self.current_call = call
                    self.backlight_lock()
                    self.show_last = True

        if talker_shown:
            return

        if self.current_call.state == 'start':
            self.__update_talker(self.current_call)
        else:
            # show last caller for few seconds, otherwise status page
            if self.show_last:
                tdiff = datetime.now() - self.current_call.entrytime
                if tdiff >= timedelta(seconds=0) and tdiff <= timedelta(seconds=5):
                    self.__update_talker(self.current_call)
                else:
                    self.show_last = False

            # show Status Page otherwise
            if not self.show_last:
               self.__update_status()

    def __update_tg(self):
        if self.current_call.state == 'start' or self.show_last:
            return "TG "+str(self.current_tg)
        else:
            if self.current_tg == 0:
               return self.get_tgname(self.current_tg)
            else:
               return "TG "+str(self.current_tg)+self.get_tgname(self.current_tg)

    def __update_ip(self):
       s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
       s.connect(('<broadcast>', 12345))  # 12345 is random port
       ipa = s.getsockname()[0]
       if len(ipa):
            self.ipa = ipa
       else:
            self.ipa = "---.---.---.---"
       return self.ipa

    def update_temp_and_load(self):
        def __get_cpu():
            load1, load5, load15 = psutil.getloadavg()
            cpu_usage = (load1/os.cpu_count()) * 100
            return f'{str(int(float(cpu_usage))):>2}'

        def __get_temp():
            try:
                with open("/sys/class/thermal/thermal_zone0/temp", "r", encoding='utf-8') as temp:
                    tempc = int(float(temp.read()) / 1000)+temp_offset
                    return str(tempc)
            except Exception as e:
                return "?"

        def __get_ext_temp():
            if not self.ext_temp_sensor:
                return False
            sensors = glob.glob("/sys/bus/w1/devices/28*/w1_slave")
            if not sensors:
                return "?"
            # show temperature from first sensor only
            sensor_file = sensors[0]
            try:
                fc = ""
                with open(sensor_file, 'r', encoding='utf-8') as f:
                          fc = f.read()
                m = re.search(r't=(?P<temp>-?\d+)', fc)
                if not m:
                    return "?"
                return str(int(float(m.group('temp')) / 1000.0))
            except Exception as e:
                logger.debug(f"__get_ext_temp() failed: {e}")
            return "?"

        ext_temp = __get_ext_temp()
        if ext_temp:
            msgc = __get_cpu()
            msgt = __get_temp()
            msgh = __get_ext_temp()
            return msgc,msgt,msgh
        else:
            msgc = __get_cpu()
            msgt = __get_temp()
            return msgc,msgt

    def svxlink_alive(self):
        """Check if the svxlink process is running using the subprocess module."""
        try:
            # Run the `pgrep` command to search for processes named "svxlink"
            result = subprocess.run(['pgrep', 'svxlink'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # If pgrep finds the process, it will return a non-empty result in stdout
            return result.returncode == 0
        except Exception as e:
            print(f"An error occurred: {e}")
            return False
        if not __is_svxlink_alive():
            self.reflector_disconnected()

    def shutdown(self):
        shutdown_msg()
        sys.exit(0)


class ScreenREMOTE(Screen):
    driver = "Remote"

def load_config(config_path):
    config = configparser.ConfigParser()

    if not os.path.exists(config_path):
        print(f"Error: Configuration file '{config_path}' does not exist.")
        sys.exit(1)

    try:
        config.read(config_path)
    except configparser.Error as e:
        print(f"Error reading configuration file '{config_path}': {e}")
        sys.exit(1)

    return config

def get_config_value(config, option, value_type=str, section='remotelcd', default=None):
    try:
        if value_type == bool:
            return config.getboolean(section, option)
        elif value_type == int:
            return config.getint(section, option)
        elif value_type == float:
            return config.getfloat(section, option)
        else:
            return config.get(section, option)
    except configparser.NoSectionError:
        print(f"Error: Section '{section}' not found in the configuration file.", file=sys.stderr)
        sys.exit(1)
    except configparser.NoOptionError:
        if default is not None:
            return default
        print(f"Error: Option '{option}' not found in section '{section}'.", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: Invalid value for option '{option}' in section '{section}': {e}", file=sys.stderr)
        sys.exit(1)

try:
    svxlog = None
    shutdown = False
    signal.signal(signal.SIGTERM, shutdown_signal_handler)
    signal.signal(signal.SIGINT, shutdown_signal_handler)

    logger = logging.getLogger('lcd')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s',
                 datefmt='%Y-%m-%d %H:%M:%S')
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.setLevel(logging.WARNING)

    config_file = 'remotelcd.ini'
    config = load_config(config_file)

    driver = "Remote"

    backlightoff_status = False
    backlight_locked = False
    backlight_time = get_config_value(config, 'backlight_time',int)
    ext_temp_sensor = get_config_value(config, 'ext_temp_sensor', bool)
    ip_address = get_config_value(config, 'ip_address', str, default="127.0.0.1")
    supported_drivers = ["Remote"]

    debug = get_config_value(config, 'debug', bool, default=False)
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="Show debugging information.", action="store_true", default=None)
    args = parser.parse_args()

    if args.debug is not None:
        debug = args.debug

    if debug:
        logger.setLevel(logging.DEBUG)

    if driver not in supported_drivers:
        print("Unsupported driver: %s. Supported drivers are: %s" % (driver, supported_drivers), file=sys.stderr)
        sys.exit(1)

    driver_class_name = "Screen%s" % driver.upper()
    driver_class = globals()[driver_class_name]

    sc = driver_class(ip_address=ip_address,ext_temp_sensor=ext_temp_sensor)
    svxlog = SvxLogMonitor(screen=sc)

    welcome_msg()
    time.sleep(3)

    while True:
        if shutdown:
            svxlog.stop_monitoring()
            sc.shutdown()

        logger.debug(f"Current TG: |{sc.current_tg}|, Last Call: |{sc.current_call}|, Pending calls: |{sc.calls}")

        sc.update_talkers_or_status()
        sc.check_backlight_lock()
        time.sleep(0.5)

except Exception as e:
    if svxlog:
        svxlog.stop_monitoring()
    raise
