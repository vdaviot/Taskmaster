#!/usr/bin/python

import cmd, sys, os, signal, yaml, datetime, time, subprocess, threading, signal

from subprocess import check_output, Popen

global com
global stream
global thread_count
global path
thread_count = None
thread_count = 0
com = {}
path = os.popen('pwd').read().replace('\n', '') + "/conf.yaml"


class Thread_kill(threading.Thread):
	def run(process_name):
		if process_name in com:
			com[process_name] == "dying"
			for p in progs:
				if p.name == process_name:
					p.suicide()
					t = time.time()
					while t + p.timeout <= time.time():
						pid = p.get_pid()
						if pid == None:
							com[process_name] = "dead"
							return
					p.get_kill()
					com[process_name] = "dead"
		return


class MyThread(threading.Thread):
	def choose(self):
		for p in progs:
			if p.name == self.name:
				return p
		return None

	def run(self):
		obj = self.choose()
		tryit = obj.restarttry
		if obj == None:
			return
		i = obj.number
		while i > 0:
			if obj.discard_out != None and obj.discard_err != None:
				with open(obj.discard_out, "a") as f:
					with open(obj.discard_err, "a") as e:
						subprocess.Popen(obj.cmd, shell=True, stdout=f, stderr=e)
						try:
							patience = os.waitpid(-1, 0)
						except OSError, err:
							com[obj.name] = "ended"
			elif obj.discard_err != None and obj.discard_out == None:
				with open(obj.discard_err, "a") as e:
					subprocess.Popen(obj.cmd, shell=True, stderr=e)
					try:
						patience = os.waitpid(-1, 0)
					except OSError, err:
						com[obj.name] = "ended"
			elif obj.discard_out != None and obj.discard_err == None:
				with open(obj.discard_out, "a") as f:
					subprocess.Popen(obj.cmd, shell=True, stdout=f)
					try:
						patience = os.waitpid(-1, 0)
					except OSError, err:
						com[obj.name] = "ended"
			else:
				subprocess.Popen(obj.cmd, shell=True)
				try:
					patience = os.waitpid(-1, 0)
				except OSError, err:
					com[obj.name] = "ended"
			verif = patience[1]
			if int(verif) != int(obj.expected):
			 	print "{} returned an error, expected {} got {}.".format(obj.name, obj.expected, verif)
			 	if tryit > 0:
			 		tryit -= 1
			 		continue
			i  = i - 1
		com[obj.name] = "ended"
		return




class Program(object):
	def get_kill(self):
		for pid in self.get_pid().split():
			if pid != None:
				try:
					os.kill(int(pid), 11)
				except OSError, err:
					print "Error \"{}\" occured when closing the {} program.".format(err, self.name)
					return
				print "Process " + self.name + " ended."

	def suicide(self):
		sign = self.get_stop_signal("programs")
		for pid in self.get_pid().split():
			if pid != None:
				try:
					os.kill(int(pid), sign)
					print "Process " + self.name + " ended."
				except OSError, err:
					print "Process {} ({}) not killed because of reason.".format(self.name, pid)

	def get_in_conf(self, arg, name, info):
		for prog in conf[arg]:
			if prog.get(name):
				i = 0
				while prog[prog.keys()[0]][i]:
					if not prog[prog.keys()[0]][i]:
						break
					if prog[prog.keys()[0]][i].keys()[0] == info:
						return prog[prog.keys()[0]][i].get(info)
					i += 1
		return None

	def	get_timer(self):
		at = time.time()
		while (self.get_pid()):
			if time.time >= at + int(self.time_period):
				return True
		return False

	def get_pid(self):
		return os.popen("pgrep " + self.name).read()

	def	get_status(self):
		if self.pid:
			return 'RUNNING'
		return 'DEAD'

	def	get_env(self, arg):
		env = {}
		env = self.get_in_conf(arg, self.name, "env")
		return env

	def	get_old_env(self):
		return os.environ

	def get_nb(self, arg):
		return self.get_in_conf(arg, self.name, "nb")

	def get_options(self, arg):
		return self.get_in_conf(arg, self.name, "options")

	def get_boot(self, arg):
		return self.get_in_conf(arg, self.name, "boot")

	def get_restart(self, arg):
		return self.get_in_conf(arg, self.name, "restart")

	def	get_expected(self, arg):
		return self.get_in_conf(arg, self.name, "expected")

	def	get_timeout(self, arg):
		return self.get_in_conf(arg, self.name, "timeout")

	def	get_nb_restart(self, arg):
		return self.get_in_conf(arg, self.name, "restarttry")

	def	get_stop_signal(self, arg):
		return self.get_in_conf(arg, self.name, "stopsignal")

	def	get_time_period(self, arg):
		return self.get_in_conf(arg, self.name, "timeperiod")

	def	get_program_discard_err(self, arg):
		discard_err = self.get_in_conf(arg, self.name, "discard_err")
		if str(discard_err)[0] == "~":
			discard_err = os.environ["HOME"] + discard_err.replace(discard_err[:1], '')
		return discard_err

	def	get_program_discard_out(self, arg):
		discard_out = self.get_in_conf(arg, self.name, "discard_out")
		if str(discard_out)[0] == "~":
			return os.environ["HOME"] + discard_out.replace(discard_out[:1], '')

	def	get_wd(self, arg):
		last = self.get_in_conf(arg, self.name, "wd")
		if last != None:
			if last[0] == "~":
				return os.environ["HOME"] + last.replace(last[:1], '')
		return last

	def	get_umask(self, arg):
		var = self.get_in_conf(arg, self.name, "umask")
		return var

	def gstatus(self):
		print "----------------------------------------------"
		print " "
		print "Program {} settings/status:".format(self.name)
		print "		- Program state = {}".format(com[self.name])
		print "		- The PID of {} is {}.".format(self.name, self.pid.split("\n", 2))
		print "		- Program {} is {}.".format(self.name, self.status)
		print "		- {} instance of {} program needed.".format(self.number, self.name)
		print "		- Restart status: {}.".format(self.restart)
		print "		- Boot status: {}.".format(self.boot)
		print "		- Program expected to return {}.".format(self.expected)
		print "		- Timeout set to {}.".format(self.timeout)
		print "		- If a problem happend, Taskmaster will restart {} {} times.".format(self.name, self.nb_restart)
		print "		- {} will shutdown if {} is send.".format(self.name, self.stop_signal)
		print "		- If a problem happend, {} will be kept alive for {} seconds.".format(self.name, self.time_period)
		print "		- {} stderr is set to {}.".format(self.name, self.discard_err)
		print "		- {} stdout is set to {}.".format(self.name, self.discard_out)
		print "		- Working directory set to {}.".format(self.wd)
		print "		- Umask variable is set to {}.".format(self.umask)
		if self.new_env != None:
			print "		- New env specified: "
			for p in self.new_env:
				print "			- {}.".format(p)
		if self.sstarted == True:
			print "		- Program {} successfuly started.".format(self.name)
		else:
			print "		- Program {} not started because of reasons.".format(self.name)
		print " "
		print "----------------------------------------------"

	def __init__(self, process_name, conf):
		where = "programs"
		self.file = conf
		self.name = process_name
		self.pid = self.get_pid()
		self.status = self.get_status()
		self.number = self.get_nb(where)
		self.boot = self.get_boot(where)
		self.restart = self.get_restart(where)
		self.expected = self.get_expected(where)
		self.timeout = self.get_timeout(where)
		self.nb_restart = self.get_nb_restart(where)
		self.stop_signal = self.get_stop_signal(where)
		self.time_period = self.get_time_period(where)
		self.discard_err = self.get_program_discard_err(where)
		self.discard_out = self.get_program_discard_out(where)
		self.wd = self.get_wd(where)
		if self.wd != None:
			try:
				os.chdir(self.wd)
			except OSError:
				print "{} directory does not exist.".format(self.wd)
		self.umask = self.get_umask(where)
		if self.umask != None:
			self.old_umask = os.umask(self.umask)
		self.new_env = self.get_env(where)
		if self.new_env != None:
			self.old_env = self.get_old_env()
		self.options = self.get_options(where)
		self.sstarted = self.get_timer()
		progs[self.name] = self
		self.cmd = ""
		if self.new_env != None:
			for cmd in self.new_env:
				pouet = cmd.keys()[0]
				self.cmd += pouet + "=" + cmd.get(pouet) + " "
		if self.options != None:
			self.cmd += self.name + " " + self.options
		else:
			self.cmd += self.name


class	Microshell(cmd.Cmd):
	intro = '\033[92m' + '\n******************************************\n****      Welcome in Taskmaster.      ****\n****    Type help to list command.    ****\n******************************************\n' + '\033[0m'
	if "USER" in os.environ:
		prompt = os.environ["USER"] + "@42>"
		user = os.environ["USER"] + "@student.42.fr"
	else:
		prompt = "Anonymous@42>"
	file = None

	def	do_status(self, name):
		'Give you the status of each programs described in the configuration file.'
		if name != "":
			for p in progs:
				if p.name == name:
					p.gstatus()
		else:
			for p in progs:
				p.gstatus()

	def do_reload(self, file):
		'Reload the configuration file.'
		for p in progs:
			try:
				kill(p.name)
			except IOError, err:
				print "Nope"
		conf = None
		init()

	def do_exit(self, arg):
		'Exit the program.'
		print "Thank you for using Taskmaster.{}".format(arg)
		finish()
		return True


	def	do_start(self, process_name):
		for p in progs:
			if p.name == process_name:
				start(process_name)

	def	do_kill(self, process_name):
		kill(process_name)

	def	do_restart(self, process_name):
		'Restart a program in the configuration file'
		self.do_kill(process_name)
		self.do_start(process_name)

# def start_progs(process_name):													#launch the prog on start
# 	if process_name == None:
# 		for smthing in conf:
# 			for prog in conf[smthing]:
# 				mythread = MyThread(name = prog[prog.keys()[0]][0]['name'])
# 				com[prog[prog.keys()[0]][0]['name']] = "starting"
# 				mythread.start()
# 	else:
# 		# for smthing in conf:
# 			# for prog in conf[smthing]:
# 				# meh = prog.keys()[0]
# 				# if meh == process_name:
# 					# print "on lance {}".format(process_name)
# 					mythread = MyThread(name = process_name)
# 					com[prog[prog.keys()[0]][0]['name']] = "starting"
# 					mythread.start()

def	kill_thread():
	for p in com:
		if com[p] != "dead" or "ready":
			kill(p)

def	kill(process_name):
	myThread = Thread_kill(name = process_name)
	myThread.start()

def signal_handler(signal, frame):
    print "You pressed {}.".format(signal)
    kill_thread()
    sys.exit(signal)

def finish():
	print ("\033[91mended:" + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + "\n" + "\033[0m")
	kill_thread()
	sys.exit(9)

def get_conf():														#return the configuration
	stream = open(path, 'r')
	try:
		return yaml.load(stream)
	except yaml.YAMLError as exc:
		print exc
		return None

def	parse_progs():
	liste = []
	for smthing in conf:
		for prog in conf[smthing]:
			meh = prog.keys()[0]
			new = Program(meh, conf)
			liste.append(new)
	return liste

def	start(process_name):
	com[process_name] = "starting"
	mythread = MyThread(name=process_name)
	mythread.start()

def init():															#init
	global	conf
	global  progs
	progs = {}
	signal.signal(signal.SIGINT, signal_handler)
	conf = get_conf()
	progs = parse_progs()
	for p in progs:
		com[p.name] = "ready"
		if p.boot == True:
			start(p.name)


if __name__ == '__main__':											#main
	init()
	Microshell().cmdloop()
