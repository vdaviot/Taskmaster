#!/usr/bin/python

import cmd, sys, os, signal, yaml, datetime, time, subprocess, threading, signal, re 
import smtplib as sm
import getpass
from subprocess import check_output, Popen
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

global com
global stream
global thread_count
global path
global People
global log
People = []
thread_count = None
thread_count = 0
com = {}
path = os.popen('pwd').read().replace('\n', '') + "/conf.yaml"
SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) for n in dir(signal) if n.startswith('SIG') and '_' not in n )

class ErrorHandling():
	def __init__(self, error):
		self.file = "error.txt"
		self.time = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
		self.error = str(self.time) + ":\n    - " + str(error) + "\n"
		self.error_write(self.error)
	
	def error_write(self, error):
		with open(self.file, 'a') as f:
			try:
				f.write(self.error)
				f.write("\n")
				f.close()
				print "\033[91m\n{}\033[0m".format(self.error)
			except IOError as err:
				myerror = ErrorHandling(err)

class User():
	def __init__(self, mail):
		self.mail = mail
		valid = self.check_addr(self.mail)
		if valid == True:
			self.passwd = getpass.getpass(prompt="Enter your password: ")
			try:
				server = sm.SMTP('smtp.gmail.com:587')
				# server = sm.SMTP('localhost')
				# server.set_debuglevel(True)
				server.starttls()
				server.login(self.mail, self.passwd)
			except sm.SMTPAuthenticationError as err:
				MyError = ErrorHandling(err)
				self.real = False
				return
		else:
			self.real = False
			return
		print "New user set:\n- {}".format(self.mail)
		self.real = True


	def	check_addr(self, mail):
		res = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', mail)
		if res == None:
			MyError = ErrorHandling("Not well formated email.")
			return False
		else:
			return True


	def	send_mail(self, sendto, content, status, obj):		#status 1 = error / status 0 = success
		dest = sendto.split("@")[0]
		msg = MIMEMultipart()
		msg['From'] = self.mail
		msg['To'] = sendto
		msg['Subject'] = "Taskmaster\'s infos"
		body = "Hello {},\nThis is an automatic message from Taskmaster.\nThe following concern the execution of your {} program.\nPlease do not reply to this e-mail.\n".format(dest, obj.name)
		if status > 0 and content:
			body += "\nThis happened to your {} program :\n    ".format(obj.name) + content
			body += "\n\nThanks you for using Taskmaster, See you soon!\n\n{}".format(os.environ["USER"])
			msg.attach(MIMEText(body, 'plain'))
			try:
				server = sm.SMTP('smtp.gmail.com:587')
				server.starttls()
				server.login(self.mail, 'lhrcdzobskxqkmnd')
				text = msg.as_string()
				server.sendmail(self.mail, sendto, text)
			except sm.SMTPException as err:
				MyError = ErrorHandling(err)

class Thread_timeperiod(threading.Thread):
	def run(self):
		if self.name in com:
			if com[self.name] == "starting":
				for p in progs:
					if p.name == self.name:
						t = time.time()
						while t + p.time_period > time.time():
							if com[self.name] != "starting":
								return
						com[self.name] = "running"
		return

def delaying(process_name):
	start(process_name)

class Thread_kill(threading.Thread):
	def run(self):
		try:
			if self.name in com:
				if com[self.name] == "restart":
					r = 1
				else:
					r = 0
				com[self.name] == "dying"
				lo = open("log.txt", "a")
				log = lo.fileno()
				for p in progs:
					if p.name == self.name:
						p.suicide()
						if p.get_pid() == "":
							com[self.name] = "dead"
							os.write(log, "{} have been stoped\n".format(self.name))
							return
						t = time.time()
						while t + p.timeout > time.time():
							pid = p.get_pid()
							if pid == "":
								com[self.name] = "dead"
								os.write(log, "{} have been ended\n".format(self.name))
								return
						p.get_kill()
						com[self.name] = "dead"
				if r == 1:
					start(self.name)
		except IOError as err:
			MyError = ErrorHandling(err)
		return

class MyThread(threading.Thread):
	def choose(self):
		for p in progs:
			if p.name == self.name:
				return p
		return None

	def run(self):
		obj = self.choose()
		tryit = obj.nb_restart
		lo = open("log.txt", "a")
		log = lo.fileno()
		patience = 0
		if obj == None:
			return
		i = obj.number
		while i > 0:
			if obj.discard_out != None and obj.discard_err != None:
				with open(obj.discard_out, "a") as f:
					with open(obj.discard_err, "a") as e:
						p = subprocess.Popen(obj.cmd, shell=True, stdout=f, stderr=e)
						myThread = Thread_timeperiod(name = obj.name)
						myThread.start()
						try:
							patience = os.waitpid(p.pid, 0)
						except OSError, err:
							com[obj.name] = "ended"
			elif obj.discard_err != None and obj.discard_out == None:
				with open(obj.discard_err, "a") as e:
					p = subprocess.Popen(obj.cmd, shell=True, stderr=e)
					myThread = Thread_timeperiod(name = obj.name)
					myThread.start()
					try:
						patience = os.waitpid(p.pid, 0)
					except OSError , err:
						com[obj.name] = "ended"
			elif obj.discard_out != None and obj.discard_err == None:
				with open(obj.discard_out, "a") as f:
					p = subprocess.Popen(obj.cmd, shell=True, stdout=f)
					myThread = Thread_timeperiod(name = obj.name)
					myThread.start()
					try:
						patience = os.waitpid(p.pid, 0)
					except OSError, err:
						com[obj.name] = "ended"
			else:
				p = subprocess.Popen(obj.cmd, shell=True)
				myThread = Thread_timeperiod(name = obj.name)
				myThread.start()
				try:
					patience = os.waitpid(p.pid, 0)
				except OSError, err:
					com[obj.name] = "ended"
			try:
				if isinstance(patience[1], int):
					if int(patience[1]) != int(obj.expected):
					 	os.write(log, "\033[91m{} returned an error, expected {} got {}.\n\033[0m".format(obj.name, obj.expected, patience[1]))
					 	obj.strstatus = "{} returned an error, expected {} got {}.\nBe carefull with the configuration file, the problem might come from yourself.\n".format(obj.name, obj.expected, patience[1])
					 	sys.stdout.flush()
					 	if tryit > 0:
					 		tryit -= 1
					 		continue
					 	elif tryit == 0:
					 		break
					 	elif tryit == -1:
					 		continue
					else:
					 	obj.strstatus = "No problem occured during {}\'s execution (returned {} as expected).".format(obj.name, obj.expected)
					i  = i - 1
				for ppl in People:
					User.send_mail(ppl, ppl.mail, obj.strstatus, obj.status, obj)
			except TypeError as err:
				MyError = ErrorHandling(err)
				return
			com[obj.name] = "ended"
		return


    
class Program(object):
	def get_kill(self):
		for pid in self.get_pid().split():
			if pid != None:
				try:
					os.kill(int(pid), 11)
				except OSError as err:
					MyError = ErrorHandling(err)
					return
				lo = open("log.txt", "a")
				log = lo.fileno()
				os.write(log, "\033[92mProcess " + self.name + " ended.\n\033[0m")

	def suicide(self):
		sign = self.get_stop_signal("programs")
		for pid in self.get_pid().split():
			if pid != None:
				try:
					os.kill(int(pid), sign)
					lo = open("log.txt", "a")
					log = lo.fileno()
					os.write(log, "\033[92mProcess " + self.name + " ended.\n\033[0m")
				except OSError as err:
					MyError = ErrorHandling(err)

	def get_in_conf(self, arg, name, info):
		try:
			for prog in conf[arg]:
				if prog.get(name):
					i = 0
					while prog[prog.keys()[0]][i]:
						if not prog[prog.keys()[0]][i]:
							break
						if prog[prog.keys()[0]][i].keys()[0] == info:
							return prog[prog.keys()[0]][i].get(info)
						i += 1
		except IndexError as err:
			print "\033[91mconf.yaml not well formated, you might take a look at it and see what\'s going on!\033[0m".format(err)
			finish(1)

		return None

	def	get_timer(self):
		at = time.time()
		while (self.get_pid()):
			if time.time >= at + int(self.time_period):
				return True
		return False

	def get_pid(self):
		pid =  os.popen("pgrep " + self.cmdname).read()
		if isinstance(pid, int) or isinstance(pid, list) or isinstance(pid, tuple) or isinstance(pid, str):
			return pid
		else:
			print "[{}]".format(pid)
			return None

	def	get_status(self):
		if self.pid:
			return 'RUNNING'
		return 'DEAD'

	def	get_cmdname(self, arg):
		cmdname = self.get_in_conf(arg, self.name, "name")
		if isinstance(cmdname, str):
			return cmdname

	def	get_env(self, arg):
		env = {}, self.get_in_conf(arg, self.name, "env")
		if isinstance(env, dict):
			return env

	def	get_old_env(self):
		return os.environ

	def get_nb(self, arg):
		nb = self.get_in_conf(arg, self.name, "nb")
		if nb >= 0 and isinstance(nb, int):
			return nb

	def get_options(self, arg):
		options = self.get_in_conf(arg, self.name, "options")
		if isinstance(options, str):
			return options

	def get_boot(self, arg):
		boot = self.get_in_conf(arg, self.name, "boot")
		if isinstance(boot, bool):
			if boot == True or False:
				return boot

	def get_restart(self, arg):
		restart = self.get_in_conf(arg, self.name, "restart")
		if isinstance(restart, int):
			return restart

	def	get_expected(self, arg):
		expected = self.get_in_conf(arg, self.name, "expected")
		if isinstance(expected, int):
			return expected

	def	get_timeout(self, arg):
		timeout = self.get_in_conf(arg, self.name, "timeout")
		if isinstance(timeout, int):
			return timeout

	def	get_nb_restart(self, arg):
		restart = self.get_in_conf(arg, self.name, "restarttry")
		if isinstance(restart, int):
			return restart

	def	get_stop_signal(self, arg):
		signal = self.get_in_conf(arg, self.name, "stopsignal")
		if isinstance(signal, int):
			return signal

	def	get_time_period(self, arg):
		time = self.get_in_conf(arg, self.name, "timeperiod")
		if isinstance(time, int):
			return time

	def	get_program_discard_err(self, arg):
		discard_err = self.get_in_conf(arg, self.name, "discard_err")
		if isinstance(discard_err, str):
			if str(discard_err)[0] == "~":
				discard_err = os.environ["HOME"] + discard_err.replace(discard_err[:1], '')
			return discard_err

	def	get_program_discard_out(self, arg):
		discard_out = self.get_in_conf(arg, self.name, "discard_out")
		if isinstance(discard_out, str):
			if str(discard_out)[0] == "~":
				return os.environ["HOME"] + discard_out.replace(discard_out[:1], '')
			return discard_out

	def	get_wd(self, arg):
		last = self.get_in_conf(arg, self.name, "wd")
		if isinstance(last, str):
			if last[0] == "~":
				return os.environ["HOME"] + last.replace(last[:1], '')
			return last

	def	get_umask(self, arg):
		var = self.get_in_conf(arg, self.name, "umask")
		if isinstance(var, int):
			return var

	def gstatus(self):
		print "----------------------------------------------"
		print " "
		if self.name:
			print "Program {} settings/status:".format(self.name)
			print "		- Program state = {}".format(com[self.name])
			if self.pid:
				print "		- The PID of {} is {}.".format(self.name, self.pid.split("\n", 2))
			if self.status:
				print "		- Program {} is {}.".format(self.name, self.status)
				if self.number:
					print "		- {} instance of {} program needed.".format(self.number, self.name)
			if self.cmdname:
				print "		- command : {}.".format(self.cmdname)
			if self.boot:
				print "		- Boot status: {}.".format(self.boot)
			if self.expected:
				print "		- Program expected to return {}.".format(self.expected)
			if self.timeout:
				print "		- Timeout set to {}.".format(self.timeout)
			if self.nb_restart:
				print "		- If a problem happend, Taskmaster will restart {} {} times.".format(self.name, self.nb_restart)
			if self.stop_signal:
				print "		- {} will shutdown if {} is send.".format(self.name, self.stop_signal)
			if self.time_period:
				print "		- If a problem happend, {} will be kept alive for {} seconds.".format(self.name, self.time_period)
			if self.discard_err:
				print "		- {} stderr is set to {}.".format(self.name, self.discard_err)
			if self.discard_out:
				print "		- {} stdout is set to {}.".format(self.name, self.discard_out)
			if self.wd:
				print "		- Working directory set to {}.".format(self.wd)
			if self.umask:
				print "		- Umask variable is set to {}.".format(self.umask)
			if self.new_env:
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
		self.cmdname = self.get_cmdname(where)
		self.pid = self.get_pid()
		self.status = self.get_status()
		self.number = self.get_nb(where)
		self.boot = self.get_boot(where)
		self.expected = self.get_expected(where)
		self.timeout = self.get_timeout(where)
		self.nb_restart = self.get_nb_restart(where)
		self.stop_signal = self.get_stop_signal(where)
		self.time_period = self.get_time_period(where)
		self.discard_err = self.get_program_discard_err(where)
		self.discard_out = self.get_program_discard_out(where)
		self.wd = self.get_wd(where)
		if self.wd:
			try:
				os.chdir(self.wd)
			except OSError as err:
				MyError = ErrorHandling(err)
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
		if self.new_env:
			for cmd in self.new_env:
				pouet = cmd.keys()[0]
				self.cmd += pouet + "=" + cmd.get(pouet) + " "
		if self.options:
			self.cmd += self.cmdname + " " + self.options
		else:
			self.cmd += self.cmdname
		self.strstatus = ""


class	Microshell(cmd.Cmd):
	intro = '\033[92m' + '\n/****************************************\\\n|***      \033[0mWelcome in Taskmaster.      \033[92m***|\n|***\033[0m    Type help to list command.\033[92m    ***|\n\\****************************************/\n' + '\033[0m'
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
			for p in com:
				print "\t{} is {}".format(p, com[p])

	def do_reload(self, file):
		'Reload the configuration file.'
		for p in progs:
			try:
				kill(p.name)
			except IOError, err:
				MyError = ErrorHandling(err)
		conf = None
		init()

	def do_EOF(self, process_name):
		'Exit the program.'
		kill_thread()
		sys.exit(0)
		return True

	def do_exit(self, arg):
		'Exit the program.'
		print "\033[92mThank you for using Taskmaster.{}\033[0m".format(arg)
		finish(0)
		return True

	def	do_user(self, mail):
		'Define a new user. Taskmaster will send you email everytime something happend. Utilisation: user <mail> <passwd>'
		if mail == "":
			for ppl in People:
				print ppl.mail
			return
		newppl = add_user(mail)
		if newppl.real == True:
			People.append(newppl)

	def	do_start(self, process_name):
		'Start a program in the configuration file'
		for p in progs:
			if p.name == process_name:
				start(process_name)

	def	do_stop(self, process_name):
		'Stop a program started by Taskmaster'
		if process_name in com:
			if com[process_name] == "running" or com[process_name] == "starting":
					kill(process_name)
			else:
				print "\033[91mCant kill {}, it\'s actually {}.\033[0m".format(process_name, com[process_name])
		else:
			print "{} not in conf file".format(process_name)

	def do_delay(self, process_name):
		'Start a program with delay'
		tab = process_name.split()
		for p in progs:
			if p.name == tab[0]:
				try:
					print "{}".format(int(tab[1]))
					t = threading.Timer(int(tab[1]), delaying, [tab[0]])
					t.start()
				except ValueError:
					print "arg2 must be an integer"
					return

	def	do_restart(self, process_name):
		'Restart a program in the configuration file'
		if process_name in com:
			if com[process_name] == "running": # proc can be kill when ... + kill can also start sometimes
				com[process_name] = "restart"
				kill(process_name)
			elif com[process_name] == "dead" or com[process_name] == "ended" or com[process_name] == "ready":
				self.do_start(process_name)
		else:
			print "[{}] is not in conf file".format(process_name)

	def	do_man(self, cmd):
		'Print the Taskmaster\'s man.'
		try:
			with open("man_taskmaster.txt", 'r') as file:
				print file.read()
				file.close()
		except IOError as err:
			MyError = ErrorHandling(err)
# .
# \'~~~-,
#  \    '-,_ 
#   \ /\    `~'~''\          M E X I C O
#   _\ \\          \/~\ 
#   \__ \\             \   
#      \ \\.             \  
#       \ \ \             `~~
#        '\\ \.             /
#         L \  \            |
#          \_\  \      o    |             _.----,
#                |       San \           !     /
#               '._      Luis \_      __/    _/
#                  \_    Potosi ''--''    __/
#                    \.__                |
#                        ''.__  __.._   __\
#                             ''     './  `

def proc_is_chilling(process_name):
	if process_name in com:
		if com[process_name] == "ready" or com[process_name] == "dead" or com[process_name] == "endead":
			return 1
		print "\033[90m{} : is busy.\033[0m".format(process_name)
	print "\033[91m{} not in the conf file.\033[0m".format(process_name)

def	kill_thread():
	for p in com:
		if com[p] != "dead" and com[p] != "ready" and com[p] != "ended":
			kill(p)

def	kill(process_name):
	if process_name in com:
		if com[process_name] == "running" or com[process_name] == "restart" or com[process_name] == "starting":
			myThread = Thread_kill(name = process_name)
			myThread.start()
		else:
			print "\033[91mCant stop {}, it is actually {}\033[0m".format(process_name, com[process_name])
	else:
		print "\033[91m{} is not in conf file\033[0m".format(process_name)

def signal_handler(signal, frame):
    print "\033[92mYou pressed {}({}).\033[0m".format(SIGNALS_TO_NAMES_DICT[signal], signal)
    kill_thread()
    sys.exit(signal)

def finish(value):
	lo = open("log.txt", "a")
	log = lo.fileno()
	os.write(log, "\033[91mended: " + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + "\n" + "\033[0m")
	kill_thread()
	try:
		os.remove('error.txt')
	except OSError as err:
		MyError = ErrorHandling(err)
	sys.exit(value)

def get_conf():
	stream = open(path, 'r')
	try:
		return yaml.load(stream)
	except yaml.YAMLError as err:
		MyError = ErrorHandling(err)
		return None

def	add_user(email):
	newppl = User(email)
	return newppl

def	parse_progs():
	liste = []
	for smthing in conf:
		try:
			for prog in conf[smthing]:
				meh = prog.keys()[0]
				new = Program(meh, conf)
				liste.append(new)
		except TypeError as err:
			MyError = ErrorHandling(err)
	return liste

def	start(process_name):
	if process_name in com:
		if com[process_name] == "ready" or com[process_name] == "dead" or com[process_name] == "ended":
			lo = open("log.txt", "a")
			log = lo.fileno()
			os.write(log, "\033[92mstarting {}\n\033[0m".format(process_name))
			com[process_name] = "starting"
			mythread = MyThread(name = process_name)
			mythread.start()
		else:
			print "\033[91mcant start {}, it is actually {}\033[0m".format(process_name, com[process_name])
	else:
		print "\033[91m{} is not in conf file\033[0m".format(process_name)

def init():
	global	conf
	global  progs
	progs = {}
	signal.signal(signal.SIGINT, signal_handler)
	lo = open("log.txt", "a")
	log = lo.fileno()
	conf = get_conf()
	progs = parse_progs()
	for p in progs:
		com[p.name] = "ready"
		if p.boot == True:
			start(p.name)


if __name__ == '__main__':
	init()
	Microshell().cmdloop()
	finish(1)
