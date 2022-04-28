# problem:check http sessions and if a source IP is related to three different user-agents or more, output it
# code procedure:
# a global variable to store the relationship of sourceIP to user-agent
# write a event which can return you the http header information
# you may need to study the datatype of Table, Set, String
# to_lower(str) return a lowercase version string of the original one
# you may use print to output the alert

# 源ip地址+用户代理信息的Table，key是源ip地址，value是记录user-agents的集合
global srcIP_user_agents: table[addr] of set[string];

# 该事件用来获取源ip以及用户代理等信息，注意：变量名是必须要有的，不管用不用得到，都得写上去！获取方式类似每次获取一行数据
event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) {
	# user-agents，源ip地址信息存储
	local user_agents = to_lower(c$http$user_agent);
	local srcIP: addr = c$id$orig_h;
	
	# 集合记录user-agents信息
	local user_agents_set: set[string];
	
	# 逻辑部分
	if (srcIP !in srcIP_user_agents) add user_agents_set[user_agents];
	else {
		user_agents_set = srcIP_user_agents[srcIP];
		add user_agents_set[user_agents];
	}
	
	# 更新global的Table中对应key值的value(srcIP值对应的user_agents)
	srcIP_user_agents[srcIP] = user_agents_set;
}

event zeek_done() {
	for (srcIP, user_agents_set in srcIP_user_agents) {
		if (|user_agents_set| >= 3) print fmt("%s is a proxy", srcIP);
	}
}
