#!/usr/bin/python
import cmd, sys, os, signal, yaml, datetime, time, subprocess

from subprocess import check_output, Popen

def get_in_conf(arg, name, info):
	for prog in conf[arg]['programs']:
		if prog.get(name):
			i = 0
			while prog[prog.keys()[0]][i]:
				if not prog[prog.keys()[0]][i]:
					break
				if prog[prog.keys()[0]][i].keys()[0] == info:
					return prog[prog.keys()[0]][i].get(info)
				i += 1
	return None

class Program(object):

	def get_pid(self):
		return os.popen("pgrep " + self.name).read()

	def	get_status(self):
		if self.pid:
			return 'RUNNING'
		return 'DEAD'

	def get_nb(self, arg):
		return get_in_conf(arg, self.name, "nb")

	def get_options(self, arg):
		return get_in_conf(arg, self.name, "options")

	def get_boot(self, arg):
		return get_in_conf(arg, self.name, "boot")

	def get_restart(self, arg):
		return get_in_conf(arg, self.name, "restart")

	def	get_expected(self, arg):
		return get_in_conf(arg, self.name, "expected")

	def	get_timeout(self, arg):
		return get_in_conf(arg, self.name, "timeout")

	def	get_nb_restart(self, arg):
		return get_in_conf(arg, self.name, "restarttry")

	def	get_stop_signal(self, arg):
		return get_in_conf(arg, self.name, "stopsignal")

	def	get_time_period(self, arg):
		return get_in_conf(arg, self.name, "timeperiod")

	def	get_program_discard_err(self, arg):
		discard_err = get_in_conf(arg, self.name, "discard_err")
		if str(discard_err)[0] == "~":
			discard_err = os.environ["HOME"] + discard_err.replace(discard_err[:1], '')
		return discard_err

	def	get_program_discard_out(self, arg):
		discard_out = get_in_conf(arg, self.name, "discard_out")
		if str(discard_out)[0] == "~":
			discard_out = os.environ["HOME"] + discard_out.replace(discard_out[:1], '')
		return discard_out

	def	get_wd(self, arg):
		last = get_in_conf(arg, self.name, "wd")
		if last[0] == "~":
			last = os.environ["HOME"] + last.replace(last[:1], '')
		return last

	def	get_umask(self, arg):
		return get_in_conf(arg, self.name, "umask")

	def gstatus(self):
		print "----------------------------------------------"
		print " "
		print "Program {} settings/status:".format(self.name)
		print "		- The PID of {} is {}.".format(self.name, self.pid.split("\n", 2))
		print "		- Program {} is {}.".format(self.name, self.status)
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
		print " "
		print "----------------------------------------------"

	def	launch(self):
		if self.boot == True:
			i = self.number
			while i > 0:
				if self.options != 'None' or False:
					subprocess.Popen([self.name, self.options])
				elif self.options == 'None' or False:
					subprocess.Popen(self.name)
				verif = os.popen("echo $?").read()
				if int(verif) != int(self.expected):
					print "{} returned an error, expected {} got {}.".format(self.name, self.expected, verif)
				i -= 1

	def	redirect(self):
		if self.discard_err != False or None:
			self.fd_err = sys.stderr = open(self.discard_err, 'w')
		if self.discard_out != False or None:
			self.fd_out = sys.stdout = open(self.discard_out, 'w')

	def	close_error_and_std(self):
		if self.discard_out != False:
			self.discard_out.close()
		if self.discard_err != False:
			self.discard_err.close()

	def __init__(self, process_name, conf):
		start = "start"
		self.file = conf
		self.name = process_name
		self.pid = self.get_pid()
		self.status = self.get_status()
		self.number = self.get_nb(start)
		self.boot = self.get_boot(start)
		self.restart = self.get_restart(start)
		self.expected = self.get_expected(start)
		self.timeout = self.get_timeout(start)
		self.nb_restart = self.get_nb_restart(start)
		self.stop_signal = self.get_stop_signal(start)
		self.time_period = self.get_time_period(start)
		self.discard_err = self.get_program_discard_err(start)
		self.discard_out = self.get_program_discard_out(start)
		self.wd = self.get_wd(start)
		self.umask = self.get_umask(start)
		self.gstatus()
		self.options = self.get_options(start)
		self.redirect()
		self.launch()
		# self.env = self.get_env()

class	Microshell(cmd.Cmd):
	intro = '\033[92m' + '\n******************************************\n****      Welcome in Taskmaster.      ****\n****    Type help to list command.    ****\n******************************************\n' + '\033[0m'
	if "USER" in os.environ:
		prompt = os.environ["USER"] + "@42>"
	else:
		prompt = "Anonymous@42>"
	file = None	


	def	do_status(self, file): # a modifier par la suite
		'Give you the status of each programs described in the configuration file.'
		for p in progs:
			print "{} program is {}.".format(p.name, p.status)

	def do_reload(self, file):
		'Reload the configuration file.'
		for p in progs:
			p.close_error_and_std()
			del p
		conf = None
		conf = get_conf()
		start_progs()

	def do_exit(self, arg):
		'Exit the program.'
		print "Thank you for using Taskmaster.{}".format(arg)
		self.close()
		finish()
		return True

	def do_get_pid(self, process_name):
		'Get the PID of the wanted program. Usage get_pid <program>.'
		pid = os.popen("pgrep " + process_name).read()
		print pid

	def	do_start(self, process_name):
		subprocess.Popen(process_name)

	def	do_kill(self, process_name):
		'Kill a process by his PID or name.'
		for p in progs:
			if p.name == process_name:
				for pid in p.get_pid().split():
					print "[{}] -> [{}]".format(pid, signal.SIGTERM)
					os.kill(int(pid), signal.SIGTERM)
					print "Process " + process_name + " killed."

	def close(self):
		if self.file:
			self.file.close()
			self.file = None

def	start(command):
	'Start a new process. Usage start <command>.'
	subprocess.Popen(command)

def finish():														#end
	print ("\033[91mended:" + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + "\n" + "\033[0m")
	quit()

def get_conf():														#return the configuration
	with open("conf.yaml", 'r') as stream:
		try:
			return yaml.load(stream)
		except yaml.YAMLError as exc:
			print(exc)
			return None

def start_progs():													#launch the prog on start
	global	progs
	progs = []
	if 'start' in conf:
		if 'programs' in conf['start']:
			progs = [Program(prog[prog.keys()[0]][0]['name'], conf) for prog in conf['start']['programs']]

def init():															#init
	global	conf
	conf = get_conf()
	start_progs()

"""
	if 'log' in conf :
	   if 'stderr' in conf['log'] :
	       sys.stderr = open(conf['log']['stderr'], 'a')
	   if 'stdout' in conf['log'] :
	       sys.stdout = open(conf['log']['stdout'], 'a')
"""

if __name__ == '__main__':											#main
	init()
	Microshell().cmdloop()