import { useState, useEffect } from "react";

const STORAGE_KEY = "cspc_v4";

const LEVELS = [
  { id: 1, title: "Rookie Analyst", xpRequired: 0, badge: "🆕" },
  { id: 2, title: "Junior Detection Engineer", xpRequired: 150, badge: "🔍" },
  { id: 3, title: "Cloud Security Engineer", xpRequired: 400, badge: "☁️" },
  { id: 4, title: "Threat Hunter", xpRequired: 700, badge: "🎯" },
  { id: 5, title: "Red/Blue Team Lead", xpRequired: 1000, badge: "⚔️" },
];

const MISSIONS = [
  // ── MISSION 1 ─────────────────────────────────────────────────────────────
  {
    id: "m1",
    title: "Mission 1: Decode the Evidence",
    subtitle: "Variables & Dictionaries",
    xpReward: 75,
    difficulty: "ROOKIE",
    diffColor: "#4ade80",
    mitre: "T1069.003",
    briefing: "An unknown user enumerated IAM users in your AWS account. CloudTrail captured the event. Your job: extract the key details using Python.",
    teachingPoints: [
      {
        concept: "What is Python? How does it work?",
        plain: "Python is a language for giving instructions to a computer. You write those instructions in a file, and Python reads them top to bottom, one line at a time. Every script you built for your lab — iam_enum.py, privilege_escalation.py — is just a list of Python instructions executed in order.\n\nLines starting with # are comments. Python ignores them. They are notes for humans reading the code.",
        code: '# This is a comment — Python skips this line\n# Your iam_enum.py starts with comments explaining the script\n\nprint("Hello, SOC")   # This line runs — prints text to screen\nprint("Script complete")',
      },
      {
        concept: "Variables — Labeling Your Evidence",
        plain: "A variable is a named container for a value. You create one by writing a name, an equals sign, then the value. Think of it like labeling an evidence bag — the label is the variable name, the contents are the value.\n\nYou can store text (called a string), numbers, or True/False values (called booleans). Strings always need quotes around them.",
        code: '# Creating variables — name = value\nattacker_name = "lab-attacker"    # string (text)\nip_address = "203.0.113.45"       # string\nevent_count = 5                    # integer (whole number)\nis_suspicious = True               # boolean (True or False)\n\n# Reading variables — just use the name\nprint(attacker_name)    # lab-attacker\nprint(event_count)      # 5\nprint(is_suspicious)    # True',
      },
      {
        concept: "Dictionaries — How CloudTrail Events Are Stored",
        plain: "A dictionary stores information as key:value pairs, wrapped in curly braces {}. Every single CloudTrail event is a dictionary — each field (like eventName, sourceIPAddress) is a key, and the actual value is what follows the colon.\n\nYou access a value by writing the dictionary name followed by the key in square brackets.",
        code: '# A dictionary — curly braces, key: value pairs\nevent = {\n    "eventName": "ListUsers",\n    "sourceIPAddress": "203.0.113.45",\n    "eventTime": "2026-03-11T21:50:01Z"\n}\n\n# Access a value using its key in square brackets\nprint(event["eventName"])        # ListUsers\nprint(event["sourceIPAddress"])  # 203.0.113.45',
      },
      {
        concept: "Nested Dictionaries — Dicts Inside Dicts",
        plain: "A dictionary value can itself be another dictionary. In CloudTrail, the userIdentity field is a nested dict — it contains its own keys like userName and accountId.\n\nTo reach a nested value, you chain two sets of square brackets: first get the outer key (which gives you the inner dict), then get the inner key from that.",
        code: '# CloudTrail userIdentity is a nested dictionary\nevent = {\n    "eventName": "ListUsers",\n    "userIdentity": {          # this value is ANOTHER dict\n        "userName": "lab-attacker",\n        "accountId": "123456789012"\n    }\n}\n\n# Step 1: event["userIdentity"] gives you the inner dict\n# Step 2: ["userName"] gets the value from that inner dict\nprint(event["userIdentity"]["userName"])   # lab-attacker\nprint(event["userIdentity"]["accountId"])  # 123456789012',
      },
      {
        concept: "Boolean Comparison — The Core of Detection",
        plain: "The == operator (double equals) compares two values and returns True or False. This is different from = (single equals) which assigns a value.\n\nThis is the foundation of every detection rule you will ever write: 'does this event match what I am looking for?'",
        code: '# Single = assigns a value to a variable\nevent_name = "ListUsers"\n\n# Double == compares two values, returns True or False\nresult = event_name == "ListUsers"   # True\nresult2 = event_name == "GetObject"  # False\n\nprint(result)    # True\nprint(result2)   # False\n\n# You can store the result in a variable\nis_recon = event_name == "ListUsers"\nprint(is_recon)  # True',
      },
    ],
    codeContext: 'event = {\n    "eventName": "ListUsers",\n    "sourceIPAddress": "203.0.113.45",\n    "eventTime": "2026-03-11T21:50:01Z",\n    "userIdentity": {\n        "userName": "lab-attacker",\n        "accountId": "123456789012"\n    }\n}',
    blanks: [
      {
        id: "b1",
        label: "Task 1 — Access a dictionary value",
        prompt: 'Print the event name from the dictionary.\n\nprint( ___ )',
        answers: ['event["eventName"]', "event['eventName']"],
        hint: 'Dictionary name, then the key in square brackets: event["keyName"]',
        explanation: 'event["eventName"] reads the value stored under the "eventName" key. In CloudTrail this is always the AWS API call name — ListUsers, AssumeRole, GetObject, etc.',
      },
      {
        id: "b2",
        label: "Task 2 — Access a nested dictionary value",
        prompt: 'Print the username. It is nested inside "userIdentity".\n\nprint( ___ )',
        answers: ['event["userIdentity"]["userName"]', "event['userIdentity']['userName']"],
        hint: 'Chain two bracket accesses. First get "userIdentity" (the inner dict), then get "userName" from it.',
        explanation: 'event["userIdentity"]["userName"] — the first brackets give you the inner dictionary, the second brackets get the value from inside it. This chaining pattern appears constantly in CloudTrail parsing.',
      },
      {
        id: "b3",
        label: "Task 3 — Store a value in a variable",
        prompt: 'Create a variable called attacker and store the username in it.\n\n___ = event["userIdentity"]["userName"]',
        answers: ["attacker"],
        hint: 'A variable name goes on the left side of =. Just the name — no quotes.',
        explanation: 'attacker = event["userIdentity"]["userName"] creates a variable called attacker and stores the username string in it. You can now use attacker anywhere instead of retyping the full dictionary access.',
      },
      {
        id: "b4",
        label: "Task 4 — Boolean comparison",
        prompt: 'Set is_suspicious to True if the eventName equals "ListUsers".\n\nis_suspicious = ___',
        answers: ['event["eventName"] == "ListUsers"', "event['eventName'] == 'ListUsers'", 'event["eventName"] == \'ListUsers\'', "event['eventName'] == \"ListUsers\""],
        hint: 'Use == (double equals) to compare. Dict access on the left, the string to match on the right.',
        explanation: 'The == operator compares the event name to the string "ListUsers" and returns True or False. This is your first detection rule — "did this event do the specific thing I am watching for?"',
      },
    ],
    recap: [
      { concept: "Comments (#)", description: "Lines starting with # are ignored by Python. Use them to explain what your code does — your lab scripts are full of them." },
      { concept: "Variables", description: "Named containers: attacker = 'lab-attacker' stores the string. Reference it by name later instead of retyping the value." },
      { concept: "Dictionaries {}", description: "Key:value pairs in curly braces. Every CloudTrail event is a dictionary. Access values with dict[\"key\"]." },
      { concept: "Nested Dictionaries", description: "Dicts inside dicts. Chain brackets: event[\"userIdentity\"][\"userName\"] drills two levels deep." },
      { concept: "Boolean Comparison (==)", description: "Double equals compares and returns True/False. Single = assigns. event[\"eventName\"] == \"ListUsers\" is your first detection rule." },
    ],
  },

  // ── MISSION 2 ─────────────────────────────────────────────────────────────
  {
    id: "m2",
    title: "Mission 2: Pattern Recognition",
    subtitle: "Lists, Loops & Conditionals",
    xpReward: 75,
    difficulty: "ROOKIE",
    diffColor: "#4ade80",
    mitre: "T1530",
    briefing: "Your SIEM flagged 5 S3 events in the last hour. One is a GetObject on aws-credentials-backup.txt from your credential_theft.py simulation. Write Python to find it automatically.",
    teachingPoints: [
      {
        concept: "Lists — Holding Multiple Events",
        plain: "A list is an ordered collection of items, wrapped in square brackets []. Items are separated by commas. CloudTrail log files give you a list of events — your job is to loop through all of them.\n\nLists can hold anything: strings, numbers, even dictionaries. You can get an item by its position (index), which starts at 0 not 1.",
        code: '# A list of strings\nevent_names = ["GetObject", "ListBuckets", "AssumeRole"]\n\n# Access by index — starts at 0\nprint(event_names[0])    # GetObject\nprint(event_names[2])    # AssumeRole\n\n# len() tells you how many items\nprint(len(event_names))  # 3\n\n# A list of dictionaries — exactly how CloudTrail works\nevents = [\n    {"eventName": "GetObject", "key": "report.csv"},\n    {"eventName": "AssumeRole", "key": None},\n]',
      },
      {
        concept: "For Loops — Processing Every Event",
        plain: "A for loop runs a block of code once for each item in a list. The variable after 'for' takes on each item's value in turn. The indented code beneath the for line is the 'loop body' — it runs on every item.\n\nIndentation is how Python knows what belongs inside the loop. Everything indented under 'for' is part of the loop.",
        code: 'events = ["GetObject", "ListBuckets", "AssumeRole"]\n\n# "event" takes the value of each item in turn\nfor event in events:\n    print(f"Checking: {event}")   # runs 3 times\n\n# Output:\n# Checking: GetObject\n# Checking: ListBuckets\n# Checking: AssumeRole\n\n# After the loop, indentation returns to normal\nprint("Loop finished")   # runs once, after all items',
      },
      {
        concept: "If / Elif / Else — Making Decisions Inside Loops",
        plain: "An if statement runs a block of code only when a condition is True. Elif ('else if') checks another condition if the first was False. Else runs if nothing matched.\n\nLike loops, indentation controls what belongs inside each branch. This is how you classify every event — ask a question about it and take the right action.",
        code: 'for event in events:\n    event_name = event["eventName"]\n\n    if event_name == "AssumeRole":\n        print("HIGH — privilege escalation")   # runs if True\n    elif event_name == "ListUsers":\n        print("MEDIUM — recon")\n    else:\n        print("LOW — normal")   # runs if nothing matched',
      },
      {
        concept: ".lower() — Case-Insensitive Matching",
        plain: "File names in CloudTrail can have mixed capitalization. .lower() is a string method — it creates a lowercase version of the string so your comparisons always work regardless of how the original was capitalized.\n\nYou attach it to any string with a dot: string.lower(). It does not change the original — it returns a new lowercase copy for you to compare against.",
        code: 'key = "Config/AWS-Credentials-Backup.txt"\n\n# Without .lower() — MISSES the file\nif "credentials" in key:\n    print("alert")   # Does NOT run — capital C breaks it\n\n# With .lower() — catches it every time\nif "credentials" in key.lower():\n    print("alert")   # Runs — key.lower() is all lowercase\n\n# key.lower() returns a new string, original unchanged\nprint(key)          # Config/AWS-Credentials-Backup.txt\nprint(key.lower())  # config/aws-credentials-backup.txt',
      },
      {
        concept: "+= Accumulator — Counting Alerts",
        plain: "The += operator adds to a variable and saves the result back into that same variable. It is shorthand for writing alert_count = alert_count + 1.\n\nYou always start a counter at 0 before the loop, then use += 1 inside the loop each time something matches. After the loop, your counter holds the total.",
        code: '# Start the counter BEFORE the loop\nalert_count = 0\n\nevents = ["GetObject", "AssumeRole", "GetObject"]\n\nfor event in events:\n    if event == "GetObject":\n        alert_count += 1   # adds 1 each time\n\n# After the loop\nprint(alert_count)   # 2\n\n# += works with any number\nscore = 10\nscore += 5    # score is now 15',
      },
    ],
    codeContext: 'events = [\n    {"eventName": "ListBuckets",  "key": None},\n    {"eventName": "GetObject",    "key": "reports/q1-sales.csv"},\n    {"eventName": "GetObject",    "key": "config/aws-credentials-backup.txt"},\n    {"eventName": "ListObjectsV2","key": None},\n    {"eventName": "GetObject",    "key": "secrets/api-keys.json"},\n]\nSENSITIVE_WORDS = ["credentials", "secrets", "api-keys", "password", "token"]\nalert_count = 0',
    blanks: [
      {
        id: "b1",
        label: "Task 1 — Write a for loop",
        prompt: "Start the loop to iterate over every event in the list.\n\nfor event in ___:",
        answers: ["events", "events:"],
        hint: "The list variable is called `events`. The for loop iterates over it.",
        explanation: "for event in events: — Python takes each dictionary from the events list one at a time and puts it into the variable 'event'. On pass 1, event = the ListBuckets dict. On pass 3, event = the aws-credentials dict.",
      },
      {
        id: "b2",
        label: "Task 2 — If statement inside a loop",
        prompt: 'Inside the loop, check if the event is a GetObject call.\n\n    if event["eventName"] == ___:',
        answers: ['"GetObject"', "'GetObject'"],
        hint: "You are comparing to a specific string. Strings need quotes around them.",
        explanation: 'Checking event["eventName"] == "GetObject" first gates the logic — only then do we check the file key. This two-step pattern avoids false positives from unrelated event types.',
      },
      {
        id: "b3",
        label: "Task 3 — Case-insensitive string check",
        prompt: 'Check if a sensitive word appears in the file key regardless of capitalization.\n\n        if word in event["key"].___(  ):',
        answers: ["lower()", "lower"],
        hint: "You need the string method that converts text to all-lowercase before comparing.",
        explanation: ".lower() normalizes the key before checking. Without it, a file named 'AWS-Credentials-Backup.txt' would slip past detection. Always normalize case in detection logic.",
      },
      {
        id: "b4",
        label: "Task 4 — Increment a counter",
        prompt: "After printing the alert, add 1 to the counter.\n\n            alert_count ___ 1",
        answers: ["+=", "+= 1"],
        hint: "+= adds the right side to the variable. alert_count += 1 is shorthand for alert_count = alert_count + 1.",
        explanation: "alert_count += 1 tallies every suspicious event found. You initialized it to 0 before the loop, and after the loop finishes it holds the total number of alerts fired across all events.",
      },
    ],
    recap: [
      { concept: "Lists []", description: "Ordered collections in square brackets. CloudTrail log files give you a list of event dictionaries to process." },
      { concept: "For Loops", description: "for event in events: runs the indented block once per item. Indentation defines what belongs inside the loop." },
      { concept: "If / Elif / Else", description: "Makes decisions inside loops. Indented code under each branch only runs when that condition is True." },
      { concept: ".lower()", description: "String method that returns a lowercase copy. Always use it before comparing file names or paths — capitalization varies." },
      { concept: "+= accumulator", description: "Adds to a variable in place. Start at 0 before the loop, use += 1 inside to count matches." },
    ],
  },

  // ── MISSION 3 ─────────────────────────────────────────────────────────────
  {
    id: "m3",
    title: "Mission 3: Build Your First Detection Rule",
    subtitle: "Functions — Reusable Detection Logic",
    xpReward: 100,
    difficulty: "JUNIOR",
    diffColor: "#60a5fa",
    mitre: "T1078.004",
    briefing: "Three attack scenarios just landed in your queue. You need one detection function you can call on any event — not rewrite the same if/else every time. This is how all your lab scripts are structured.",
    teachingPoints: [
      {
        concept: "What is a Function — and Why Use One?",
        plain: "A function is a named, reusable block of code. You write the logic once, give it a name, and call it by name whenever you need it. All four of your lab scripts (iam_enum.py, privilege_escalation.py, etc.) are built from functions — each phase is its own function that main() calls in sequence.\n\nWithout functions you would copy-paste the same detection logic everywhere. With functions you write it once and it works everywhere.",
        code: '# Without functions — copy-paste nightmare\nif event1["eventName"] == "AssumeRole":\n    print("HIGH")\nif event2["eventName"] == "AssumeRole":\n    print("HIGH")\n\n# With a function — write once, use anywhere\ndef check_risk(event):\n    if event["eventName"] == "AssumeRole":\n        print("HIGH")\n\ncheck_risk(event1)   # reuse\ncheck_risk(event2)   # reuse',
      },
      {
        concept: "Defining a Function — def, Name, Parameters",
        plain: "You define a function with the def keyword, followed by the function name, parentheses (which hold any inputs), and a colon. The indented block beneath is the function body — it only runs when you call the function.\n\nParameters are the inputs listed in the parentheses. They become variables inside the function body.",
        code: '# Structure: def function_name(parameter):\n#                indented body\n\ndef greet(name):           # name is the parameter\n    print(f"Hello {name}") # body — runs when called\n\n# Nothing happens yet — just defined\n\n# Call it by name, pass in a value\ngreet("Greg")    # Hello Greg\ngreet("Alice")   # Hello Alice\n\n# From YOUR lab — same pattern:\ndef get_current_identity(session):   # session is the parameter\n    sts = session.client("sts")\n    ...',
      },
      {
        concept: "Return Values — Getting Data Back Out",
        plain: "A function can send data back to whoever called it using the return keyword. The moment Python hits return, the function exits and passes the value back.\n\nIn your privilege_escalation.py, assume_privileged_role() returns the temp credentials on success, or None on failure. The caller then decides what to do with that result.",
        code: 'def analyze(event_name):\n    if event_name == "AssumeRole":\n        return "HIGH"     # exits function, sends "HIGH" back\n    if event_name == "ListUsers":\n        return "MEDIUM"\n    return "LOW"          # default if nothing matched\n\n# Capture the return value in a variable\nrisk = analyze("AssumeRole")   # risk = "HIGH"\nrisk = analyze("ListBuckets")  # risk = "LOW"\n\nprint(risk)   # LOW',
      },
      {
        concept: "Returning a Dictionary — Structured Results",
        plain: "Functions can return any type — including a dictionary. Returning a dict instead of a plain string lets you send back multiple pieces of information at once: the risk level, the reason, and the MITRE technique ID.\n\nThe caller can then access individual fields from the returned dict using the same bracket syntax you learned in Mission 1.",
        code: 'def analyze_event(event):\n    if event["eventName"] == "AssumeRole":\n        return {\n            "risk": "HIGH",\n            "reason": "Role assumption detected",\n            "mitre": "T1078.004"\n        }\n    return {"risk": "LOW", "reason": "Normal", "mitre": "N/A"}\n\n# Call and capture the returned dict\nresult = analyze_event({"eventName": "AssumeRole"})\n\n# Access fields from the returned dict\nprint(result["risk"])    # HIGH\nprint(result["mitre"])   # T1078.004',
      },
      {
        concept: ".get() — Safe Dictionary Access",
        plain: "Using dict['key'] crashes if the key does not exist. The .get() method is a safer alternative — if the key is missing it returns a default value instead of crashing.\n\nThis matters for CloudTrail logs because not every event has every field. S3 events have a key field but STS events do not.",
        code: 'event = {"eventName": "AssumeRole"}\n\n# This CRASHES if "key" is not in the dict\nvalue = event["key"]              # KeyError!\n\n# .get() returns None by default if key is missing\nvalue = event.get("key")          # None — no crash\n\n# Or provide your own default\nvalue = event.get("key", "")      # "" — no crash\n\n# From YOUR lab scripts — this pattern is everywhere:\nevent_name = event.get("eventName", "")',
      },
    ],
    codeContext: 'SENSITIVE_KEYS = ["credentials", "secrets", "api-keys", "password", "token", "backup"]\n\ndef analyze_event(event):\n    event_name = event.get("eventName", "")\n    key = event.get("requestParameters", {}).get("key", "") or ""\n    # your detection logic goes here\n    ...',
    blanks: [
      {
        id: "b1",
        label: "Task 1 — Define a function",
        prompt: "Define a function called analyze_event that takes one parameter called event.\n\n___ analyze_event(event):",
        answers: ["def", "def "],
        hint: "The keyword for defining a function is three letters.",
        explanation: "def is short for 'define'. def analyze_event(event): creates a reusable function named analyze_event. Every time you call analyze_event(some_event), Python runs the body with that event as the parameter.",
      },
      {
        id: "b2",
        label: "Task 2 — Safe dictionary access with .get()",
        prompt: 'Read the eventName safely. Return "" if the key is missing.\n\nevent_name = event.___("eventName", "")',
        answers: ["get", "get()"],
        hint: "The safe dictionary access method that takes a key and a default value.",
        explanation: "event.get('eventName', '') returns the value if the key exists, or '' if it doesn't — instead of crashing. You will see this in every production CloudTrail parser because logs can be inconsistent.",
      },
      {
        id: "b3",
        label: "Task 3 — Return a dictionary",
        prompt: 'When AssumeRole is detected, return a structured HIGH risk result.\n\nif event_name == "AssumeRole":\n    ___ {"risk": "HIGH", "reason": "Role assumption", "mitre": "T1078.004"}',
        answers: ["return"],
        hint: "The keyword that sends a value back to the caller and exits the function.",
        explanation: "return sends the dictionary back to whoever called analyze_event(). They can then access result['risk'] or result['mitre']. Returning structured data is far more useful than just printing.",
      },
      {
        id: "b4",
        label: "Task 4 — Return with the right string value",
        prompt: 'Complete the MEDIUM risk return for enumeration events.\n\nif event_name in ["ListUsers", "ListRoles", "ListBuckets"]:\n    return {"risk": ___, "reason": f"Enumeration: {event_name}", "mitre": "T1069.003"}',
        answers: ['"MEDIUM"', "'MEDIUM'"],
        hint: "You are returning a string inside a dict. Strings need quotes.",
        explanation: '"MEDIUM" is the string value for the risk field. ListUsers, ListRoles, and ListBuckets are all enumeration calls that credential_theft.py runs during Phase 2 recon — together they map to T1069.003.',
      },
    ],
    recap: [
      { concept: "def keyword", description: "Defines a reusable function. def analyze_event(event): creates a block that runs whenever you call analyze_event(something)." },
      { concept: "Parameters", description: "Inputs to the function listed in parentheses. When called, the passed value becomes available inside the body as that variable name." },
      { concept: "return", description: "Sends a value back to the caller and immediately exits the function. The caller captures it: result = analyze_event(event)." },
      { concept: "Returning a dictionary", description: "Return a dict to send multiple values back at once — risk, reason, MITRE ID. Caller accesses fields with result['risk'] etc." },
      { concept: ".get()", description: "Safe dict access: event.get('key', '') returns the default instead of crashing if the key is missing. Essential for real CloudTrail parsing." },
    ],
  },

  // ── MISSION 4 ─────────────────────────────────────────────────────────────
  {
    id: "m4",
    title: "Mission 4: The Attack Chain Analyzer",
    subtitle: "Classes — Building a Real Detection Tool",
    xpReward: 125,
    difficulty: "ENGINEER",
    diffColor: "#fbbf24",
    mitre: "T1552.005",
    briefing: "The full credential_theft.py chain just ran against your environment. You need a CloudTrailAnalyzer that ingests multiple events, remembers findings across all of them, and produces a report. Standalone functions can't do this — you need a class.",
    teachingPoints: [
      {
        concept: "Why Classes? The Problem with Standalone Functions",
        plain: "Functions are great for one operation, but they forget everything when they return. If you want to process 50 CloudTrail events and remember all the findings, standalone functions make you pass data around everywhere.\n\nA class solves this by bundling data AND functions together into one object. The object remembers its own state — like a running notebook that accumulates findings as you feed it events.",
        code: '# With functions — awkward, must pass data everywhere\ndef analyze(event, findings_list):     # must carry the list around\n    findings_list.append("finding")\n    return findings_list\n\nfindings = []\nfindings = analyze(event1, findings)   # pass and return\nfindings = analyze(event2, findings)   # every single time\n\n# With a class — clean, object holds its own state\nanalyzer = CloudTrailAnalyzer()\nanalyzer.ingest(event1)    # object remembers findings internally\nanalyzer.ingest(event2)\nanalyzer.report()          # all findings are already there',
      },
      {
        concept: "Defining a Class and __init__",
        plain: "You define a class with the class keyword and a name. Inside it, __init__ is a special method that Python calls automatically when you create an instance of the class. This is where you set up the object's starting state.\n\nThe double underscores around init (called 'dunder') mark it as a special Python method.",
        code: 'class CloudTrailAnalyzer:\n\n    def __init__(self, analyst_name):  # runs on creation\n        # Set up starting state here\n        self.analyst_name = analyst_name\n        self.events = []       # empty list — grows as we ingest\n        self.findings = []     # empty list — grows as we detect\n\n# Creating an instance calls __init__ automatically\nanalyzer = CloudTrailAnalyzer("Greg")\nprint(analyzer.analyst_name)   # Greg\nprint(analyzer.events)         # []',
      },
      {
        concept: "self — The Object Referring to Itself",
        plain: "Every method in a class must have self as its first parameter. self refers to the specific instance you created. self.findings means 'THIS object's findings list' — not a global variable.\n\nWhen you call analyzer.ingest(event), Python automatically passes the analyzer object as self — you never pass it yourself.",
        code: 'class CloudTrailAnalyzer:\n    def __init__(self, analyst_name):\n        self.analyst_name = analyst_name\n        self.findings = []           # stored ON the object\n\n    def add_finding(self, finding):  # self is always first\n        self.findings.append(finding)\n\n# Two separate instances — completely independent\nanalyzer1 = CloudTrailAnalyzer("Greg")\nanalyzer2 = CloudTrailAnalyzer("Alice")\n\nanalyzer1.add_finding("AssumeRole alert")\nprint(len(analyzer1.findings))  # 1\nprint(len(analyzer2.findings))  # 0 — totally separate',
      },
      {
        concept: "Methods — Functions That Belong to a Class",
        plain: "Methods are functions defined inside a class. They work exactly like regular functions except they always receive self as the first parameter, giving them access to all the object's stored data.\n\nFrom your lab: the four phases in credential_theft.py (simulate_imds_retrieval, enumerate_with_stolen_creds, escalate_privileges, exfiltrate_data) are perfect candidates to become class methods.",
        code: 'class CloudTrailAnalyzer:\n    def __init__(self, analyst_name):\n        self.analyst_name = analyst_name\n        self.events = []\n        self.findings = []\n\n    def ingest(self, event):          # method — takes an event\n        self.events.append(event)     # adds to the object\'s list\n        self._analyze(event)          # calls another method\n\n    def _analyze(self, event):        # _ means "internal use"\n        if event.get("eventName") == "AssumeRole":\n            self.findings.append("HIGH: Role assumption")\n\n    def report(self):                 # method — no extra params\n        print(f"Analyst: {self.analyst_name}")\n        print(f"Findings: {len(self.findings)}")',
      },
      {
        concept: "Putting It Together — Creating and Using an Instance",
        plain: "Once your class is defined, you create an instance by calling the class name like a function. Then you call methods on it using dot notation. The object accumulates state across every method call.\n\nThis is exactly how your detection pipeline should work: create the analyzer, feed it events one by one, then call report() at the end.",
        code: '# Create the instance — __init__ runs automatically\nanalyzer = CloudTrailAnalyzer("Greg")\n\n# Feed it the full credential_theft.py attack chain\nattack_events = [\n    {"eventName": "ListUsers"},\n    {"eventName": "AssumeRole"},\n    {"eventName": "GetObject"},\n]\n\nfor event in attack_events:\n    analyzer.ingest(event)    # object remembers each one\n\n# Object has accumulated all findings\nanalyzer.report()\n# Analyst: Greg\n# Findings: 1',
      },
    ],
    codeContext: 'class CloudTrailAnalyzer:\n    def __init__(self, analyst_name):\n        self.analyst_name = analyst_name\n        self.events = []\n        self.findings = []\n\n    def ingest(self, event):\n        self.events.append(event)\n        self._analyze(event)\n\n    def _analyze(self, event):\n        # detection logic here\n        ...\n\n    def report(self):\n        # print summary here\n        ...',
    blanks: [
      {
        id: "b1",
        label: "Task 1 — Define a class",
        prompt: "Start the class definition.\n\n___ CloudTrailAnalyzer:",
        answers: ["class", "class "],
        hint: "The keyword for defining a class blueprint.",
        explanation: "class defines a blueprint. CloudTrailAnalyzer is the name. Every time you write analyzer = CloudTrailAnalyzer('Greg'), Python uses this blueprint to stamp out a new independent object with its own data.",
      },
      {
        id: "b2",
        label: "Task 2 — The constructor method",
        prompt: "What is the special method that runs automatically when an instance is created?\n\ndef ___(self, analyst_name):",
        answers: ["__init__"],
        hint: "Double underscores on each side. Short for 'initialize'.",
        explanation: "__init__ is the constructor. Python calls it automatically when you do CloudTrailAnalyzer('Greg'). It is where you set up starting state — empty lists, stored parameters — using self. variables.",
      },
      {
        id: "b3",
        label: "Task 3 — Store data on the object with self",
        prompt: "Inside __init__, store analyst_name on the object so every method can access it.\n\n___ = analyst_name",
        answers: ["self.analyst_name"],
        hint: "To store data on the object permanently, prefix the variable name with self.",
        explanation: "self.analyst_name = analyst_name stores the value on the object. Without self., it would just be a local variable that disappears when __init__ finishes. The self. prefix is what makes data persist across method calls.",
      },
      {
        id: "b4",
        label: "Task 4 — Add an item to a list on the object",
        prompt: "Inside ingest(), add the incoming event to the object's events list.\n\nself.events.___(event)",
        answers: ["append(event)", "append"],
        hint: "The list method for adding one item to the end.",
        explanation: "self.events.append(event) grows the object's event log on every ingest() call. After feeding it the full credential_theft.py chain of 6 API calls, self.events would hold all 6 event dictionaries.",
      },
      {
        id: "b5",
        label: "Task 5 — Call another method from within the class",
        prompt: "Inside ingest(), after appending the event, call the _analyze method on the same object.\n\n___.  _analyze(event)",
        answers: ["self", "self."],
        hint: "To call another method on the same object, use the keyword that refers to the current instance.",
        explanation: "self._analyze(event) calls the _analyze method on this same object. Using self. is how methods talk to each other inside a class. The leading underscore on _analyze signals it is an internal method not meant to be called from outside.",
      },
    ],
    recap: [
      { concept: "class keyword", description: "Defines a blueprint for objects. Each instance created from it gets its own independent copy of all data." },
      { concept: "__init__", description: "The constructor — runs automatically on creation. Sets up initial state with self. variables that persist for the object's lifetime." },
      { concept: "self", description: "Refers to the specific instance. self.findings means THIS object's list — not a global. Always the first parameter of every method." },
      { concept: "Methods", description: "Functions inside a class. They get self automatically, giving them access to all the object's stored data." },
      { concept: ".append()", description: "Adds one item to the end of a list. self.events.append(event) grows the log on the object with every ingest() call." },
      { concept: "State persistence", description: "self. variables survive between method calls. The object accumulates knowledge across every ingest() — unlike a function that forgets on return." },
    ],
  },
];

function loadSave() {
  const keys = [STORAGE_KEY, "cspc_v3", "cspc_v2", "cspc_save_v2", "cspc_save"];
  for (const key of keys) {
    try {
      const raw = localStorage.getItem(key);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (key !== STORAGE_KEY) {
          localStorage.setItem(STORAGE_KEY, raw);
          localStorage.removeItem(key);
        }
        return parsed;
      }
    } catch (e) {}
  }
  return null;
}

function normalize(s) {
  return (s || "")
    .trim()
    .replace(/[\u201C\u201D\u201E\u201F\u275D\u275E]/g, '"')
    .replace(/[\u2018\u2019\u201A\u201B\u275B\u275C]/g, "'")
    .replace(/\s+/g, " ")
    .replace(/'/g, '"')
    .toLowerCase();
}

function isCorrect(userInput, acceptedAnswers) {
  const n = normalize(userInput);
  return acceptedAnswers.some(a => normalize(a) === n);
}

const S = { minHeight: "100vh", background: "#030712", color: "#f1f5f9", padding: 16, fontFamily: "monospace" };
const card = (extra = {}) => ({ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 16, ...extra });
const btn = (bg, extra = {}) => ({ background: bg, border: "none", color: "white", fontWeight: "bold", padding: "12px 16px", borderRadius: 12, cursor: "pointer", fontFamily: "monospace", fontSize: 14, width: "100%", ...extra });

export default function App() {
  const saved = loadSave();
  const [xp, setXp] = useState(saved ? saved.xp : 0);
  const [completed, setCompleted] = useState(saved ? saved.completed : []);
  const [history, setHistory] = useState(saved ? saved.history : {});
  const [view, setView] = useState("hub");
  const [mission, setMission] = useState(null);
  const [teachIdx, setTeachIdx] = useState(0);
  const [answers, setAnswers] = useState({});
  const [hintsShown, setHintsShown] = useState({});
  const [graded, setGraded] = useState(null);
  const [saveFlash, setSaveFlash] = useState(false);

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ xp, completed, history })); } catch (e) {}
  }, [xp, completed, history]);

  const level = LEVELS.reduce((best, l) => xp >= l.xpRequired ? l : best, LEVELS[0]);
  const nextLevel = LEVELS.find(l => l.xpRequired > xp) || null;
  const progress = nextLevel
    ? Math.min(100, ((xp - level.xpRequired) / (nextLevel.xpRequired - level.xpRequired)) * 100)
    : 100;

  function startMission(m) {
    setMission(m); setTeachIdx(0); setAnswers({}); setHintsShown({}); setGraded(null);
    setView("briefing");
  }

  function submitAnswers() {
    const n = mission.blanks.length;
    const base = Math.floor(mission.xpReward / n);
    const remainder = mission.xpReward - base * n;
    const worth = mission.blanks.map((_, i) => i === n - 1 ? base + remainder : base);
    let earned = 0;
    const results = mission.blanks.map((b, i) => {
      const userAnswer = (answers[b.id] || "").trim();
      const correct = isCorrect(userAnswer, b.answers);
      const hintUsed = !!hintsShown[b.id];
      const blankXp = correct ? Math.max(0, worth[i] - (hintUsed ? 10 : 0)) : 0;
      earned += blankXp;
      return { ...b, userAnswer, correct, hintUsed, blankXp, xpPerBlank: worth[i] };
    });
    earned = Math.min(mission.xpReward, Math.max(0, earned));
    const correctCount = results.filter(r => r.correct).length;
    setGraded({ results, earned, correct: correctCount, total: n });
    const prevEarned = history[mission.id] ? history[mission.id].earned : 0;
    const delta = earned - prevEarned;
    if (!completed.includes(mission.id)) {
      setXp(x => x + earned);
      setCompleted(c => [...c, mission.id]);
    } else if (delta !== 0) {
      setXp(x => Math.max(0, x + delta));
    }
    setHistory(h => ({ ...h, [mission.id]: { earned, correct: correctCount, total: n } }));
    setView("grade");
  }

  function doSave() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ xp, completed, history })); } catch (e) {}
    setSaveFlash(true); setTimeout(() => setSaveFlash(false), 2000);
  }

  function doReset() {
    if (!window.confirm("Reset all progress?")) return;
    setXp(0); setCompleted([]); setHistory({});
    try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
    setView("hub");
  }

  // ── HUB ──────────────────────────────────────────────────────────────────
  if (view === "hub") return (
    <div style={S}>
      <div style={{ maxWidth: 600, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 20 }}>
          <div style={{ fontSize: 20, fontWeight: "bold", color: "#22d3ee" }}>☁️ CLOUD SECURITY PYTHON BOOTCAMP</div>
          <div style={{ fontSize: 12, color: "#64748b", marginTop: 4 }}>cloud-attack-detection-lab edition</div>
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginBottom: 12 }}>
          <button onClick={doSave} style={{ ...btn("#0891b2", { width: "auto", padding: "4px 12px", fontSize: 11 }) }}>{saveFlash ? "Saved!" : "💾 Save"}</button>
          <button onClick={doReset} style={{ ...btn("#7f1d1d", { width: "auto", padding: "4px 12px", fontSize: 11 }) }}>↺ Reset</button>
        </div>

        <div style={card({ borderColor: "#164e63", marginBottom: 16 })}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
            <div>
              <div style={{ color: "#22d3ee", fontWeight: "bold" }}>{level.badge} {level.title}</div>
              <div style={{ color: "#64748b", fontSize: 12 }}>Greg Lewis</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ color: "#fbbf24", fontWeight: "bold", fontSize: 20 }}>{xp} XP</div>
              <div style={{ color: "#475569", fontSize: 11 }}>{completed.length}/{MISSIONS.length} missions</div>
            </div>
          </div>
          {nextLevel && <>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#475569", marginBottom: 4 }}>
              <span>→ {nextLevel.badge} {nextLevel.title}</span>
              <span>{nextLevel.xpRequired - xp} XP to go</span>
            </div>
            <div style={{ background: "#1e293b", borderRadius: 4, height: 6 }}>
              <div style={{ background: "#0891b2", borderRadius: 4, height: 6, width: `${progress}%`, transition: "width 0.5s" }} />
            </div>
          </>}
        </div>

        <div style={card({ marginBottom: 16 })}>
          <div style={{ color: "#475569", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 8 }}>Ranks</div>
          {LEVELS.map(l => (
            <div key={l.id} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: xp >= l.xpRequired ? "#67e8f9" : "#334155", padding: "3px 0" }}>
              <span>{l.badge}</span><span style={{ flex: 1 }}>{l.title}</span>
              <span>{l.xpRequired} XP</span>
              {xp >= l.xpRequired && <span style={{ color: "#4ade80" }}>✓</span>}
            </div>
          ))}
        </div>

        <div style={{ color: "#475569", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 8 }}>Missions</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
          {MISSIONS.map((m, i) => {
            const unlocked = i === 0 || completed.includes(MISSIONS[i - 1].id);
            const done = completed.includes(m.id);
            const hist = history[m.id];
            return (
              <div key={m.id} onClick={() => unlocked && startMission(m)}
                style={{ ...card({ borderColor: done ? "#14532d" : unlocked ? "#164e63" : "#1e293b", background: done ? "#052e16" : "#0f172a", opacity: unlocked ? 1 : 0.35, cursor: unlocked ? "pointer" : "default" }) }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 11, fontWeight: "bold", color: m.diffColor }}>{m.difficulty}</span>
                      <span style={{ fontSize: 11, color: "#475569" }}>{m.mitre}</span>
                      {done && <span style={{ fontSize: 11, color: "#4ade80" }}>✓ COMPLETE</span>}
                    </div>
                    <div style={{ fontWeight: "bold", color: "#f1f5f9", fontSize: 14 }}>{m.title}</div>
                    <div style={{ color: "#64748b", fontSize: 12 }}>{m.subtitle}</div>
                    {done && hist && <div style={{ color: "#334155", fontSize: 11, marginTop: 4 }}>+{hist.earned} XP · {hist.correct}/{hist.total} correct</div>}
                  </div>
                  <div style={{ color: "#fbbf24", fontWeight: "bold", fontSize: 13, marginLeft: 12 }}>+{m.xpReward}</div>
                </div>
                {!unlocked && <div style={{ color: "#334155", fontSize: 11, marginTop: 6 }}>🔒 Complete previous mission to unlock</div>}
              </div>
            );
          })}
        </div>
        {completed.length > 0 && (
          <button onClick={() => setView("results")} style={btn("#0f172a", { border: "1px solid #164e63", color: "#22d3ee" })}>📊 Full Results & Learning Summary</button>
        )}
      </div>
    </div>
  );

  // ── RESULTS ───────────────────────────────────────────────────────────────
  if (view === "results") {
    const doneMissions = MISSIONS.filter(m => completed.includes(m.id));
    const totalCorrect = Object.values(history).reduce((s, h) => s + (h.correct || 0), 0);
    const totalBlanks = Object.values(history).reduce((s, h) => s + (h.total || 0), 0);
    return (
      <div style={S}>
        <div style={{ maxWidth: 600, margin: "0 auto" }}>
          <button onClick={() => setView("hub")} style={{ background: "none", border: "none", color: "#475569", cursor: "pointer", fontSize: 13, marginBottom: 16 }}>← Hub</button>
          <div style={{ textAlign: "center", marginBottom: 20 }}>
            <div style={{ fontSize: 20, fontWeight: "bold", color: "#22d3ee" }}>📊 Learning Results</div>
            <div style={{ fontSize: 12, color: "#64748b" }}>{level.badge} {level.title} · {xp} XP</div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 20 }}>
            {[["Total XP", xp, "#fbbf24"], ["Accuracy", totalBlanks > 0 ? Math.round(totalCorrect / totalBlanks * 100) + "%" : "0%", "#4ade80"], ["Missions", `${completed.length}/${MISSIONS.length}`, "#60a5fa"]].map(([label, val, color]) => (
              <div key={label} style={card({ textAlign: "center" })}>
                <div style={{ fontWeight: "bold", fontSize: 18, color }}>{val}</div>
                <div style={{ fontSize: 11, color: "#475569" }}>{label}</div>
              </div>
            ))}
          </div>
          {doneMissions.map(m => {
            const hist = history[m.id];
            return (
              <div key={m.id} style={card({ marginBottom: 16 })}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <div style={{ fontWeight: "bold", color: "#f1f5f9", fontSize: 14 }}>{m.title}</div>
                  <div style={{ color: "#fbbf24", fontWeight: "bold" }}>+{hist && hist.earned} XP</div>
                </div>
                <div style={{ color: "#475569", fontSize: 11, marginBottom: 12 }}>{hist && hist.correct}/{hist && hist.total} correct · MITRE {m.mitre}</div>
                <div style={{ color: "#0891b2", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 8 }}>Concepts</div>
                {m.recap.map((r, i) => (
                  <div key={i} style={{ borderLeft: "2px solid #164e63", paddingLeft: 10, marginBottom: 10 }}>
                    <div style={{ color: "#67e8f9", fontSize: 12, fontWeight: "bold" }}>{r.concept}</div>
                    <div style={{ color: "#64748b", fontSize: 11, lineHeight: 1.6 }}>{r.description}</div>
                  </div>
                ))}
              </div>
            );
          })}
          <button onClick={() => setView("hub")} style={btn("#0891b2")}>← Mission Hub</button>
        </div>
      </div>
    );
  }

  // ── BRIEFING ──────────────────────────────────────────────────────────────
  if (view === "briefing" && mission) return (
    <div style={S}>
      <div style={{ maxWidth: 600, margin: "0 auto" }}>
        <button onClick={() => setView("hub")} style={{ background: "none", border: "none", color: "#475569", cursor: "pointer", fontSize: 13, marginBottom: 16 }}>← Hub</button>
        <div style={{ background: "#1a0000", border: "1px solid #7f1d1d", borderRadius: 12, padding: 16, marginBottom: 16 }}>
          <div style={{ color: "#f87171", fontWeight: "bold", marginBottom: 8 }}>📡 INCOMING ALERT</div>
          <div style={{ color: "#cbd5e1", fontSize: 13, lineHeight: 1.7 }}>{mission.briefing}</div>
        </div>
        <div style={card({ marginBottom: 16 })}>
          <div style={{ color: "#22d3ee", fontWeight: "bold", marginBottom: 6 }}>Objective</div>
          <div style={{ color: "#94a3b8", fontSize: 13 }}>{mission.subtitle}</div>
          <div style={{ display: "flex", gap: 16, marginTop: 8, fontSize: 12 }}>
            <span style={{ color: "#fbbf24" }}>+{mission.xpReward} XP max</span>
            <span style={{ color: "#475569" }}>MITRE {mission.mitre}</span>
            <span style={{ color: "#475569" }}>{mission.blanks.length} questions</span>
          </div>
        </div>
        <button onClick={() => setView("learn")} style={btn("#0891b2")}>Begin Training →</button>
      </div>
    </div>
  );

  // ── LEARN ─────────────────────────────────────────────────────────────────
  if (view === "learn" && mission) {
    const tp = mission.teachingPoints[teachIdx];
    const isLast = teachIdx === mission.teachingPoints.length - 1;
    return (
      <div style={S}>
        <div style={{ maxWidth: 600, margin: "0 auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <button onClick={() => teachIdx === 0 ? setView("briefing") : setTeachIdx(i => i - 1)} style={{ background: "none", border: "none", color: "#475569", cursor: "pointer", fontSize: 13 }}>← Back</button>
            <span style={{ color: "#475569", fontSize: 12 }}>Concept {teachIdx + 1} / {mission.teachingPoints.length}</span>
          </div>
          <div style={{ display: "flex", gap: 4, marginBottom: 16 }}>
            {mission.teachingPoints.map((_, i) => (
              <div key={i} style={{ flex: 1, height: 4, borderRadius: 2, background: i <= teachIdx ? "#0891b2" : "#1e293b" }} />
            ))}
          </div>
          <div style={card({ borderColor: "#164e63", marginBottom: 16 })}>
            <div style={{ color: "#22d3ee", fontWeight: "bold", fontSize: 15, marginBottom: 10 }}>📖 {tp.concept}</div>
            <div style={{ color: "#cbd5e1", fontSize: 13, lineHeight: 1.8, marginBottom: 14, whiteSpace: "pre-wrap" }}>{tp.plain}</div>
            <div style={{ background: "#020617", border: "1px solid #1e293b", borderRadius: 8, padding: 12 }}>
              <div style={{ color: "#475569", fontSize: 11, marginBottom: 6 }}>EXAMPLE</div>
              <pre style={{ color: "#86efac", fontSize: 12, overflowX: "auto", whiteSpace: "pre-wrap", margin: 0, lineHeight: 1.7 }}>{tp.code}</pre>
            </div>
          </div>
          <button onClick={() => isLast ? setView("challenge") : setTeachIdx(i => i + 1)} style={btn("#0891b2")}>
            {isLast ? "Start Challenge →" : "Next Concept →"}
          </button>
        </div>
      </div>
    );
  }

  // ── CHALLENGE ─────────────────────────────────────────────────────────────
  if (view === "challenge" && mission) {
    const xpPerBlank = Math.floor(mission.xpReward / mission.blanks.length);
    return (
      <div style={S}>
        <div style={{ maxWidth: 600, margin: "0 auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <button onClick={() => setView("learn")} style={{ background: "none", border: "none", color: "#475569", cursor: "pointer", fontSize: 13 }}>← Training</button>
            <span style={{ color: "#fbbf24", fontWeight: "bold", fontSize: 13 }}>+{mission.xpReward} XP available</span>
          </div>
          <div style={{ background: "#020617", border: "1px solid #1e293b", borderRadius: 12, padding: 12, marginBottom: 16 }}>
            <div style={{ color: "#475569", fontSize: 11, marginBottom: 6 }}>CONTEXT — from your lab</div>
            <pre style={{ color: "#86efac", fontSize: 11, overflowX: "auto", whiteSpace: "pre-wrap", margin: 0, lineHeight: 1.7 }}>{mission.codeContext}</pre>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 16 }}>
            {mission.blanks.map(b => (
              <div key={b.id} style={card()}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span style={{ color: "#22d3ee", fontSize: 12, fontWeight: "bold" }}>{b.label}</span>
                  <span style={{ color: "#854d0e", fontSize: 11 }}>+{xpPerBlank} XP</span>
                </div>
                <pre style={{ color: "#94a3b8", fontSize: 12, whiteSpace: "pre-wrap", marginBottom: 10, lineHeight: 1.7 }}>{b.prompt}</pre>
                <input
                  style={{ width: "100%", background: "#020617", border: "1px solid #334155", borderRadius: 8, padding: "8px 12px", color: "#86efac", fontSize: 13, fontFamily: "monospace", outline: "none", boxSizing: "border-box" }}
                  placeholder="Type your answer..."
                  value={answers[b.id] || ""}
                  onChange={e => setAnswers(a => ({ ...a, [b.id]: e.target.value }))}
                />
                {!hintsShown[b.id] ? (
                  <button onClick={() => setHintsShown(h => ({ ...h, [b.id]: true }))}
                    style={{ background: "none", border: "none", color: "#713f12", cursor: "pointer", fontSize: 11, marginTop: 6, fontFamily: "monospace", padding: 0 }}>
                    💡 Show hint (-10 XP)
                  </button>
                ) : (
                  <div style={{ marginTop: 8, background: "#1c1200", border: "1px solid #713f12", borderRadius: 8, padding: "8px 12px", color: "#fde68a", fontSize: 11 }}>
                    💡 {b.hint}
                  </div>
                )}
              </div>
            ))}
          </div>
          <button onClick={submitAnswers} style={btn("#15803d")}>Submit Answers →</button>
        </div>
      </div>
    );
  }

  // ── GRADE ─────────────────────────────────────────────────────────────────
  if (view === "grade" && graded && mission) {
    const pct = Math.round(graded.correct / graded.total * 100);
    const scoreColor = pct === 100 ? "#4ade80" : pct >= 60 ? "#fbbf24" : "#f87171";
    return (
      <div style={S}>
        <div style={{ maxWidth: 600, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 20 }}>
            <div style={{ fontSize: 36, marginBottom: 4 }}>{pct === 100 ? "🎯" : pct >= 60 ? "📈" : "📚"}</div>
            <div style={{ fontSize: 20, fontWeight: "bold", color: scoreColor }}>
              {pct === 100 ? "Perfect Score!" : pct >= 60 ? "Good Work!" : "Keep Practicing!"}
            </div>
            <div style={{ color: "#64748b", fontSize: 12, marginTop: 4 }}>
              {graded.correct}/{graded.total} correct · +{graded.earned}/{mission.xpReward} XP earned
            </div>
          </div>

          <div style={card({ marginBottom: 16 })}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#475569", marginBottom: 4 }}>
              <span>Score</span><span>{pct}%</span>
            </div>
            <div style={{ background: "#1e293b", borderRadius: 4, height: 8, marginBottom: 10 }}>
              <div style={{ background: scoreColor, borderRadius: 4, height: 8, width: `${pct}%`, transition: "width 0.5s" }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
              <span style={{ color: "#94a3b8" }}>XP Earned</span>
              <span style={{ color: "#fbbf24", fontWeight: "bold" }}>+{graded.earned} / {mission.xpReward}</span>
            </div>
          </div>

          <div style={{ color: "#475569", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 8 }}>Answer Review</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
            {graded.results.map(r => (
              <div key={r.id} style={{ background: r.correct ? "#052e16" : "#1a0000", border: `1px solid ${r.correct ? "#14532d" : "#7f1d1d"}`, borderRadius: 12, padding: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <span style={{ color: "#94a3b8", fontSize: 12, fontWeight: "bold" }}>{r.label}</span>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    {r.hintUsed && <span style={{ fontSize: 10, color: "#713f12" }}>hint used</span>}
                    <span style={{ fontSize: 12, fontWeight: "bold", color: r.correct ? "#4ade80" : "#f87171" }}>
                      {r.correct ? `✓ +${r.blankXp} XP` : "✗ 0 XP"}
                    </span>
                  </div>
                </div>
                <pre style={{ color: "#64748b", fontSize: 11, whiteSpace: "pre-wrap", lineHeight: 1.6, marginBottom: 10 }}>{r.prompt}</pre>
                <div style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span style={{ color: "#475569", fontSize: 11, minWidth: 72 }}>You wrote:</span>
                    <code style={{ fontSize: 12, padding: "2px 8px", borderRadius: 4, background: r.correct ? "#14532d" : "#7f1d1d", color: r.correct ? "#86efac" : "#fca5a5" }}>
                      {r.userAnswer || "(blank)"}
                    </code>
                  </div>
                  {!r.correct && (
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ color: "#475569", fontSize: 11, minWidth: 72 }}>Correct:</span>
                      <code style={{ fontSize: 12, padding: "2px 8px", borderRadius: 4, background: "#14532d", color: "#86efac" }}>
                        {r.answers[0]}
                      </code>
                    </div>
                  )}
                </div>
                <div style={{ borderTop: "1px solid #1e293b", paddingTop: 10 }}>
                  <div style={{ color: "#0891b2", fontSize: 11, fontWeight: "bold", marginBottom: 4 }}>Why this answer:</div>
                  <div style={{ color: "#64748b", fontSize: 11, lineHeight: 1.7 }}>{r.explanation}</div>
                </div>
              </div>
            ))}
          </div>

          <div style={card({ marginBottom: 16 })}>
            <div style={{ color: "#0891b2", fontSize: 11, textTransform: "uppercase", letterSpacing: 2, marginBottom: 10 }}>Concepts from this mission</div>
            {mission.recap.map((r, i) => (
              <div key={i} style={{ borderLeft: "2px solid #164e63", paddingLeft: 10, marginBottom: 10 }}>
                <div style={{ color: "#67e8f9", fontSize: 12, fontWeight: "bold" }}>{r.concept}</div>
                <div style={{ color: "#64748b", fontSize: 11, lineHeight: 1.6 }}>{r.description}</div>
              </div>
            ))}
          </div>

          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={() => setView("results")} style={btn("#0f172a", { flex: 1, border: "1px solid #1e293b", color: "#94a3b8" })}>📊 Results</button>
            <button onClick={() => setView("hub")} style={btn("#0891b2", { flex: 1 })}>Mission Hub →</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ ...S, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: 36, marginBottom: 12 }}>☁️</div>
        <div style={{ color: "#22d3ee", fontWeight: "bold", marginBottom: 16 }}>CLOUD SECURITY PYTHON BOOTCAMP</div>
        <button onClick={() => setView("hub")} style={btn("#0891b2", { width: "auto", padding: "10px 24px" })}>Start →</button>
      </div>
    </div>
  );
}