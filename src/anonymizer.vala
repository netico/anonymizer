/* main.vala
 *
 * Copyright (C) 2018 netico@riseup.net
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using Gtk;

// Setup                                                                      //
// -------------------------------------------------------------------------- //
const string NIC = "wlan0";
const int TOR_UID = 121;
const string TOR_USER = "debian-tor";

const int TOR_PORT = 56662;
const int TOR_DNS_PORT = 56663;
const string VIRTUAL_ADDRESS = "10.192.0.0/10";
const string IPTABLES_BIN = "/sbin/iptables";

// Buttons                                                                    //
// -------------------------------------------------------------------------- //

// Quit
public void on_quit_clicked (Button source)
{
	Gtk.main_quit ();
    Process.exit (0);

    // TODO - Drop /tmp/start_tor.sh
}
// Start Tor
public void on_start_tor_clicked (Button source, TextView console_view)
{
	try {

		int tor_pid_int = -1;
		string tor_pid = shell_sync ("pidof tor");
		tor_pid.scanf ("%d", &tor_pid_int);

		if (tor_pid_int > 0)
		{
			console_view.buffer.text = "Tor is already running";
			return;
		}

		var file = File.new_for_path ("/tmp/anonymizer.log");
		if (file.query_exists ())
		{
			file.delete ();
		}
		var file_stream = file.create (FileCreateFlags.NONE);
		var data_stream = new DataOutputStream (file_stream);
        data_stream.put_string
        (
			"Tor made easy "
			+ "(transparently routing traffic through Tor)"
			+ "\n"
		);

		string torrc = "SOCKSPort 127.0.0.1:56661\n"
		+ "TransPort 127.0.0.1:56662 IsolateClientAddr IsolateClientProtocol "
		+ "IsolateDestAddr IsolateDestPort\n"
		+ "DNSPort 127.0.0.1:56663\n"
		+ "VirtualAddrNetworkIPv4 10.192.0.0/10\n"
		+ "AutomapHostsOnResolve 1\n"
		+ "Log notice file /tmp/anonymizer.log\n";

		string config = "/tmp/anonymizer.cnf";
        file = File.new_for_path (config);
        if (file.query_exists ())
        {
            file.delete ();
        }
        var dos = new DataOutputStream
        (
			file.create (FileCreateFlags.REPLACE_DESTINATION)
		);
        string text = torrc;
        uint8[] data = text.data;
        long written = 0;
        while (written < data.length)
        {
            written += dos.write (data[written:data.length]);
        }
		string permissions;
		permissions = shell_sync ("chmod -R 666 /tmp/anonymizer.log"); // FIXME
		shell_run_as_async
		(
			"/usr/bin/tor --quiet -f /tmp/anonymizer.cnf",
			TOR_USER,
			"/tmp",
			"start-tor.sh"
		);
		log_file_monitor (console_view, "/tmp/anonymizer.log");
	}
	catch (Error e)
	{
		console_view.buffer.text = e.message;
	}
}
// Stop Tor
public void on_stop_tor_clicked (Button source, TextView console_view)
{

	int tor_pid_int = -1;
	string tor_pid = shell_sync ("pidof tor");
	tor_pid.scanf ("%d", &tor_pid_int);

	if (tor_pid_int > 0)
	{
		string shell_command = "kill " + tor_pid_int.to_string ();
		string pkexec;
		pkexec = shell_run_as
		(
			shell_command,
			"root",
			"/tmp",
			"stop_tor.sh"
		);
		console_view.buffer.text = "Tor has stopped working";
	}
	else
	{
		console_view.buffer.text = "Tor is not running";
	}
}

// Enable proxy
public void on_enable_proxy_clicked (Button source, TextView console_view)
{
	//on_reset_netfilter_clicked (source, console_view);
	//on_restart_tor_clicked (source, console_view);

	//string resolv_conf =
	var file = File.new_for_path ("/etc/resolv.conf");

    try {
        var dis = new DataInputStream (file.read ());
        string line;
        var resolv_conf = new StringBuilder ();
        while ((line = dis.read_line (null)) != null)
        {
			if ("nameserver" in line)
			{
				if (line.contains ("127.0.0.1") == false)
				{
					resolv_conf.append (line + "\n");
				}
			}
        }
		string resolv_conf_new = resolv_conf.str + "nameserver 127.0.0.1\n";

		string shell_command = "echo \"" + resolv_conf_new
		+ "\"> /etc/resolv.conf;\n"
		+ IPTABLES_BIN
		+ " -v -t nat -A OUTPUT -d " + VIRTUAL_ADDRESS.to_string()
		+ " -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT "
		+ "--to-ports " + TOR_PORT.to_string() + ";\n"
		+ IPTABLES_BIN + " -v -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp "
		+ "--dport 53 -j REDIRECT --to-ports " + TOR_DNS_PORT.to_string() + ";\n"
		+ IPTABLES_BIN + " -v -t nat -A OUTPUT -m owner --uid-owner "
		+ TOR_UID.to_string() + " -j RETURN;\n"
		+ IPTABLES_BIN + " -v -t nat -A OUTPUT -o lo -j RETURN;\n"
		+ IPTABLES_BIN + " -v -t nat -A OUTPUT -p tcp -m tcp "
		+ " --tcp-flags FIN,SYN,RST,ACK SYN "
		+ " -j REDIRECT --to-ports " + TOR_PORT.to_string() + ";\n"
		+ IPTABLES_BIN + " -v -A INPUT -m state --state ESTABLISHED -j ACCEPT;\n"
		+ IPTABLES_BIN + " -v -A INPUT -i lo -j ACCEPT;\n"
		+ IPTABLES_BIN + " -v -A INPUT -j DROP;\n"
		+ IPTABLES_BIN + " -v -A FORWARD -j DROP;\n"
		+ IPTABLES_BIN + " -v -A OUTPUT -m state --state INVALID -j DROP;\n"
		+ IPTABLES_BIN + " -v -A OUTPUT -m state --state ESTABLISHED -j ACCEPT;\n"
		+ IPTABLES_BIN + " -v -A OUTPUT -o " + NIC + " -m owner "
		+ " --uid-owner " + TOR_UID.to_string()
		+ " -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state "
		+ " --state NEW -j ACCEPT;\n"
		+ IPTABLES_BIN + " -v -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT;\n"
		+ IPTABLES_BIN + " -v -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp "
		+ " --dport " + TOR_PORT.to_string()
		+ " --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT;\n"
		+ IPTABLES_BIN + " -v -A OUTPUT -j DROP;\n"
		+ IPTABLES_BIN + " -v -P INPUT DROP;\n"
		+ IPTABLES_BIN + " -v -P FORWARD DROP;\n"
		+ IPTABLES_BIN + " -v -P OUTPUT DROP;\n";

		string pkexec;
		pkexec = shell_run_as
		(
			shell_command,
			"root",
			"/tmp",
			"enable_proxy.sh"
		);
		console_view.buffer.text = "Rules:\n" + pkexec;

    } catch (Error e) {
        console_view.buffer.text = e.message;
    }


}
// Reset netfilter
public void on_reset_netfilter_clicked (Button source, TextView console_view)
{
	string shell_command = IPTABLES_BIN
	+ " -v -P INPUT ACCEPT;\n"
	+ IPTABLES_BIN + " -P FORWARD ACCEPT;\n"
	+ IPTABLES_BIN + " -P OUTPUT ACCEPT;\n"
	+ IPTABLES_BIN + " -t nat -P PREROUTING ACCEPT;\n"
	+ IPTABLES_BIN + " -t nat -P POSTROUTING ACCEPT;\n"
	+ IPTABLES_BIN + " -t nat -P OUTPUT ACCEPT;\n"
	+ IPTABLES_BIN + " -t mangle -P PREROUTING ACCEPT;\n"
	+ IPTABLES_BIN + " -t mangle -P OUTPUT ACCEPT;\n"
	+ IPTABLES_BIN + " -F;\n"
	+ IPTABLES_BIN + " -X;\n"
	+ IPTABLES_BIN + " -t nat -F;\n"
	+ IPTABLES_BIN + " -t nat -X;\n"
	+ IPTABLES_BIN + " -t mangle -F;\n"
	+ IPTABLES_BIN + " -t mangle -X;\n";

	string pkexec;
	pkexec = shell_run_as
	(
		shell_command,
		"root",
		"/tmp",
		"reset_netfilter.sh"
	);
	console_view.buffer.text = "All rules are deleted";
}

// Shell                                                                      //
// -------------------------------------------------------------------------- //

// Sync method
private string shell_sync (string cmd)
{
    try {
        int exit_code;
        string std_out;
        Process.spawn_command_line_sync (cmd, out std_out, null, out exit_code);
        return std_out;
    }
    catch (Error e)
    {
        return (e.message);
    }
}
// Async method
private bool shell_async (string[] args)
{
    try {
        Process.spawn_async
        (
			null, args, null, SpawnFlags.SEARCH_PATH, null, null
		);
        return true;
    }
    catch (Error e)
    {
        stderr.printf (e.message);
        return false;
    }
}
// pkexec sync
private string shell_run_as (string cmd, string user, string dir, string script)
{
	try
	{
		string program = dir + "/" + script;
        var file = File.new_for_path (program);
        if (file.query_exists ())
        {
            file.delete ();
        }
        var dos = new DataOutputStream
        (
			file.create (FileCreateFlags.REPLACE_DESTINATION)
		);
        string text = cmd;
        uint8[] data = text.data;
        long written = 0;
        while (written < data.length)
        {
            written += dos.write (data[written:data.length]);
        }
        string pkexec;
		pkexec = shell_sync ("pkexec --user " + user + " /bin/sh " + program);
		if (file.query_exists ())
        {
            file.delete ();
        }
        return pkexec;
    }
    catch (Error e)
    {
        return (e.message);
    }
}

// pkexec sync
private void shell_run_as_async (string cmd, string user, string dir, string script)
{
	try
	{
		string program = dir + "/" + script;
        var file = File.new_for_path (program);
        if (file.query_exists ())
        {
            file.delete ();
        }
        var dos = new DataOutputStream
        (
			file.create (FileCreateFlags.REPLACE_DESTINATION)
		);
        string text = cmd;
        uint8[] data = text.data;
        long written = 0;
        while (written < data.length)
        {
            written += dos.write (data[written:data.length]);
        }
        shell_async
		({
			"pkexec",
			"--user",
			user,
			"/bin/sh",
			program
		});
    }
    catch (Error e)
    {
        stderr.printf (e.message);
    }
}

// Log                                                                        //
// -------------------------------------------------------------------------- //

private void log_file_monitor (TextView console_view, string log_file)
{
	// Reference to log file
    var log = File.new_for_path (log_file);
	try
	{
		FileMonitor monitor = log.monitor (FileMonitorFlags.NONE, null);
		MainLoop loop = new MainLoop ();
		monitor.changed.connect ((src, dest, event) =>
		{
			string event_string = event.to_string ();
			if (event_string == "G_FILE_MONITOR_EVENT_DELETED")
			{
				loop.quit ();
			}
			if (event_string == "G_FILE_MONITOR_EVENT_CHANGED")
			{
				try
				{
					var dis = new DataInputStream (log.read ());
					string line;
					var log_console = new StringBuilder ();

					// Read lines until end of file (null) is reached
					while ((line = dis.read_line (null)) != null)
					{
						log_console.append (line + "\n");
					}
					console_view.buffer.text = log_console.str;
				}
				catch (Error e)
				{
					console_view.buffer.text = (e.message);
				}
			}
		});
		loop.run ();
    }
    catch (Error e)
    {
        console_view.buffer.text = e.message;
    }
}

// Main                                                                       //
// -------------------------------------------------------------------------- //

int main (string[] args)
{
	Gtk.init (ref args);

	try
	{
		var b = new Builder ();
		b.add_from_file ("/usr/share/anonymizer/anonymizer.glade");
		b.connect_signals (null);

		var window = b.get_object ("window") as Window;
		window.show_all ();

		// Console
		var console_view = b.get_object ("console") as TextView;
		console_view.buffer.text = "This program helps you setup network " +
		"interface to use Tor as transparent proxy." +
		"\nThis software is very experimental and you should only use this if "
		+ "you know what you are doing. \n\nEnjoy! \n\nAnd RTFM.";

		// Statusbar
		var regex = new Regex ("[a-zA-Z]| ");
		// Linux version
		string linux_v_a = shell_sync("uname -r");
		string linux_v_b = "Linux " + linux_v_a;
		// iptables version
		string iptables_v_a = shell_sync(IPTABLES_BIN + " -V");
        string iptables_v_b = regex.replace (iptables_v_a, -1, 0, "");
        string iptables_v_c = "iptables " + iptables_v_b;
		// Tor version
		string tor_v_a = shell_sync("/usr/bin/tor --version");
		string tor_v_b = tor_v_a.substring (0, 21);
		string tor_v_c = regex.replace (tor_v_b, -1, 0, "");
		string tor_v_d = "Tor " + tor_v_c;
		// pkexec version
		string pkexec_v_a = shell_sync("pkexec --version");
		string pkexec_v_b = regex.replace (pkexec_v_a, -1, 0, "");
		string pkexec_v_c = " pkexec " + pkexec_v_b;
		string sysinfo = linux_v_b + iptables_v_c + tor_v_d + pkexec_v_c;
		var alphanum = new Regex ("[^a-zA-Z0-9-.| ]");
		string sbar_text = alphanum.replace (sysinfo, -1, 0, " ");
		var statusbar = b.get_object ("statusbar") as Statusbar;
		var context_id = statusbar.get_context_id ("statusbar");
		statusbar.push (context_id, sbar_text);

		Gtk.main ();

	}
	catch (Error e)
	{
		stderr.printf (e.message);
		return 1;
	}
	return 0;
}
