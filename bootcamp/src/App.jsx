import { useState, useEffect } from "react";

const STORAGE_KEY = "cspc_v4";

const LEVELS = [
  { id: 1, title: "Rookie Analyst",           xpRequired: 0,   badge: "🆕" },
  { id: 2, title: "Junior Detection Engineer", xpRequired: 150, badge: "🔍" },
  { id: 3, title: "Cloud Security Engineer",   xpRequired: 325, badge: "☁️" },
  { id: 4, title: "Threat Hunter",             xpRequired: 525, badge: "🎯" },
  { id: 5, title: "Red/Blue Team Lead",        xpRequired: 700, badge: "⚔️" },
];

const MISSIONS = [
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
        concept: "What is Python?",
        plain: "Python is a language for giving instructions to a computer. You write instructions in a file and Python reads them top to bottom, one line at a time. Every script in your lab — iam_enum.py, privilege_escalation.py — is just a list of Python instructions executed in order.\n\nLines starting with # are comments. Python ignores them entirely.",
        code: '# This is a comment — Python skips this line\n# iam_enum.py starts with comments explaining the script\n\nprint("Hello, SOC")   # This line runs\nprint("Script complete")',
      },
      {
        concept: "Variables — Labeling Your Evidence",
        plain: "A variable is a named container for a value. You create one by writing a name, an equals sign, then the value. Like labeling an evidence bag.\n\nStrings (text) need quotes. Numbers and True/False don't.",
        code: 'attacker_name = "lab-attacker"   # string\nip_address    = "203.0.113.45"   # string\nevent_count   = 5                # integer\nis_suspicious = True             # boolean\n\nprint(attacker_name)   # lab-attacker\nprint(event_count)     # 5',
      },
      {
        concept: "Dictionaries — How CloudTrail Events Are Stored",
        plain: "A dictionary stores key:value pairs in curly braces {}. Every CloudTrail event IS a dictionary. You access values using their key in square brackets.",
        code: 'event = {\n    "eventName": "ListUsers",\n    "sourceIPAddress": "203.0.113.45",\n    "eventTime": "2026-03-11T21:50:01Z"\n}\n\nprint(event["eventName"])        # ListUsers\nprint(event["sourceIPAddress"])  # 203.0.113.45',
      },
      {
        concept: "Nested Dictionaries — Dicts Inside Dicts",
        plain: "A dictionary value can itself be another dictionary. In CloudTrail, userIdentity is a nested dict. You chain square brackets to drill in.",
        code: 'event = {\n    "eventName": "ListUsers",\n    "userIdentity": {\n        "userName": "lab-attacker",\n        "accountId": "123456789012"\n    }\n}\n\n# Chain brackets to reach nested values\nprint(event["userIdentity"]["userName"])   # lab-attacker',
      },
      {
        concept: "Boolean Comparison — The Core of Detection",
        plain: "== (double equals) compares two values and returns True or False. This is different from = (single equals) which assigns a value. Every detection rule you write uses ==.",
        code: 'event_name = "ListUsers"\n\n# Single = assigns\n# Double == compares\nresult  = event_name == "ListUsers"   # True\nresult2 = event_name == "GetObject"   # False\n\nis_recon = event_name == "ListUsers"\nprint(is_recon)  # True',
      },
    ],
    codeContext: 'event = {\n    "eventName": "ListUsers",\n    "sourceIPAddress": "203.0.113.45",\n    "eventTime": "2026-03-11T21:50:01Z",\n    "userIdentity": {\n        "userName": "lab-attacker",\n        "accountId": "123456789012"\n    }\n}',
    blanks: [
      {
        id: "b1", label: "Task 1 — Access a dictionary value",
        prompt: 'Print the event name.\n\nprint( ___ )',
        answers: ['event["eventName"]', "event['eventName']"],
        hint: 'dictionary_name["key_name"]',
        explanation: 'event["eventName"] reads the value under "eventName". CloudTrail always stores the API call name here — ListUsers, AssumeRole, GetObject, etc.',
      },
      {
        id: "b2", label: "Task 2 — Nested dictionary access",
        prompt: 'Print the username nested inside "userIdentity".\n\nprint( ___ )',
        answers: ['event["userIdentity"]["userName"]', "event['userIdentity']['userName']"],
        hint: 'First get "userIdentity" (the inner dict), then get "userName" from that.',
        explanation: 'Chaining brackets drills into nested dicts. This pattern appears constantly in CloudTrail parsing.',
      },
      {
        id: "b3", label: "Task 3 — Store a value in a variable",
        prompt: 'Create a variable called attacker and store the username in it.\n\n___ = event["userIdentity"]["userName"]',
        answers: ["attacker"],
        hint: 'Variable name goes on the left side of =. No quotes.',
        explanation: 'attacker = ... stores the username so you can reference it by name anywhere in the script instead of retyping the full dict access.',
      },
      {
        id: "b4", label: "Task 4 — Boolean comparison",
        prompt: 'Set is_suspicious = True if the eventName equals "ListUsers".\n\nis_suspicious = ___',
        answers: ['event["eventName"] == "ListUsers"', "event['eventName'] == 'ListUsers'"],
        hint: 'Use == to compare. Dict access on the left, string on the right.',
        explanation: '== returns True or False. This is your first detection rule — "did this event do the thing I am watching for?"',
      },
    ],
    recap: [
      { concept: "Comments (#)", description: "Ignored by Python. Used to explain code — your lab scripts are full of them." },
      { concept: "Variables", description: "Named containers. attacker = 'lab-attacker' stores the string for reuse." },
      { concept: "Dictionaries {}", description: "Key:value pairs. Every CloudTrail event is a dictionary." },
      { concept: "Nested Dictionaries", description: "Dicts inside dicts. Chain brackets: event[\"userIdentity\"][\"userName\"]." },
      { concept: "Boolean Comparison (==)", description: "Double equals compares and returns True/False. The foundation of every detection rule." },
    ],
  },

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
        plain: "A list is an ordered collection wrapped in square brackets []. CloudTrail gives you a list of events. Lists can hold strings, numbers, or dictionaries. Index starts at 0.",
        code: 'event_names = ["GetObject", "ListBuckets", "AssumeRole"]\n\nprint(event_names[0])    # GetObject\nprint(event_names[2])    # AssumeRole\nprint(len(event_names))  # 3',
      },
      {
        concept: "For Loops — Processing Every Event",
        plain: "A for loop runs a block of code once for each item in a list. The indented block beneath the for line is the loop body. Indentation is how Python knows what belongs inside.",
        code: 'events = ["GetObject", "ListBuckets", "AssumeRole"]\n\nfor event in events:\n    print(f"Checking: {event}")   # runs 3 times\n\nprint("Done")   # runs once after the loop',
      },
      {
        concept: "If / Elif / Else — Making Decisions",
        plain: "If runs a block when a condition is True. Elif checks another condition. Else runs if nothing matched. Indentation controls what belongs inside each branch.",
        code: 'for event in events:\n    name = event["eventName"]\n    if name == "AssumeRole":\n        print("HIGH — escalation")\n    elif name == "ListUsers":\n        print("MEDIUM — recon")\n    else:\n        print("LOW — normal")',
      },
      {
        concept: ".lower() — Case-Insensitive Matching",
        plain: "File names in CloudTrail can have mixed capitalization. .lower() returns a lowercase copy so your comparisons work regardless of the original case.",
        code: 'key = "Config/AWS-Credentials-Backup.txt"\n\n# Without .lower() — MISSES the file\nif "credentials" in key:\n    print("alert")   # Does NOT run\n\n# With .lower() — catches it every time\nif "credentials" in key.lower():\n    print("alert")   # Runs',
      },
      {
        concept: "+= Accumulator — Counting Alerts",
        plain: "+= adds to a variable and saves the result back. alert_count += 1 is shorthand for alert_count = alert_count + 1. Always initialize to 0 before the loop.",
        code: 'alert_count = 0\n\nfor event in events:\n    if event == "GetObject":\n        alert_count += 1\n\nprint(alert_count)   # however many matched',
      },
    ],
    codeContext: 'events = [\n    {"eventName": "ListBuckets",  "key": None},\n    {"eventName": "GetObject",    "key": "reports/q1-sales.csv"},\n    {"eventName": "GetObject",    "key": "config/aws-credentials-backup.txt"},\n    {"eventName": "ListObjectsV2","key": None},\n    {"eventName": "GetObject",    "key": "secrets/api-keys.json"},\n]\nSENSITIVE_WORDS = ["credentials", "secrets", "api-keys", "password", "token"]\nalert_count = 0',
    blanks: [
      {
        id: "b1", label: "Task 1 — Write a for loop",
        prompt: "Iterate over every event in the list.\n\nfor event in ___:",
        answers: ["events", "events:"],
        hint: "The list variable is called `events`.",
        explanation: "for event in events: — each pass puts the next dictionary into the variable 'event'.",
      },
      {
        id: "b2", label: "Task 2 — If statement",
        prompt: 'Check if the event is a GetObject call.\n\n    if event["eventName"] == ___:',
        answers: ['"GetObject"', "'GetObject'"],
        hint: "You're comparing to a string. Strings need quotes.",
        explanation: 'Filtering on "GetObject" first gates the logic before checking the file key — avoiding false positives.',
      },
      {
        id: "b3", label: "Task 3 — Case-insensitive check",
        prompt: 'Check if a sensitive word is in the key regardless of capitalization.\n\n        if word in event["key"].___(  ):',
        answers: ["lower()", "lower"],
        hint: "The string method that returns an all-lowercase copy.",
        explanation: ".lower() normalizes the key so 'AWS-Credentials-Backup.txt' matches 'credentials'.",
      },
      {
        id: "b4", label: "Task 4 — Increment a counter",
        prompt: "Add 1 to the alert counter.\n\n            alert_count ___ 1",
        answers: ["+=", "+= 1"],
        hint: "+= adds the right side to the variable.",
        explanation: "alert_count += 1 tallies every suspicious event found across the full log.",
      },
    ],
    recap: [
      { concept: "Lists []", description: "Ordered collections. CloudTrail log files give you a list of event dicts." },
      { concept: "For Loops", description: "for event in events: runs the indented block once per item." },
      { concept: "If / Elif / Else", description: "Makes decisions. Indented code under each branch runs only when True." },
      { concept: ".lower()", description: "Returns a lowercase copy. Always use it before comparing file names." },
      { concept: "+= accumulator", description: "Adds to a variable in place. Initialize at 0 before the loop." },
    ],
  },

  {
    id: "m3",
    title: "Mission 3: Arm the Toolkit",
    subtitle: "Imports, Modules & the Standard Library",
    xpReward: 75,
    difficulty: "ROOKIE",
    diffColor: "#4ade80",
    mitre: "T1059.006",
    briefing: "Before your lab scripts can talk to AWS, read files, or handle errors — they need tools. Those tools come from libraries loaded with import statements. The first lines of every one of your scripts are imports. This mission teaches you exactly what each one does.",
    teachingPoints: [
      {
        concept: "What is an Import?",
        plain: "Python has a small built-in core. Everything else — AWS access, JSON parsing, timestamps — lives in separate modules. The import statement loads a module so you can use it.\n\nWithout importing, Python has no idea what boto3 or json means.",
        code: '# Without importing — NameError crash\nclient = boto3.client("iam")   # NameError!\n\n# With importing — works\nimport boto3\nclient = boto3.client("iam")   # works',
      },
      {
        concept: "import boto3 — The AWS SDK",
        plain: "boto3 is the official AWS SDK for Python. It wraps all AWS API calls so you can make them from Python without building raw HTTP requests.\n\nEvery lab script uses boto3. boto3.client() connects to a specific AWS service. boto3.Session() creates a session with a specific profile.",
        code: 'import boto3\n\n# Connect to specific AWS services\nclient = boto3.client("iam")   # IAM\ns3     = boto3.client("s3")    # S3\nsts    = boto3.client("sts")   # STS (for AssumeRole)\n\n# Session with lab-attacker profile — from your scripts\nsession = boto3.Session(\n    profile_name="lab-attacker",\n    region_name="us-east-1"\n)',
      },
      {
        concept: "import json — Parsing CloudTrail Logs",
        plain: "CloudTrail stores log files as JSON. The json module converts JSON strings into Python dictionaries you already know how to work with.\n\njson.loads() converts a JSON string INTO a dict. json.dumps() converts a dict BACK to a JSON string.",
        code: 'import json\n\nraw = \'{"eventName": "ListUsers", "sourceIPAddress": "1.2.3.4"}\'\n\n# String → dict\nevent = json.loads(raw)\nprint(event["eventName"])   # ListUsers\n\n# Dict → readable string\nprint(json.dumps(event, indent=4))',
      },
      {
        concept: "import os — Environment Variables",
        plain: "The os module accesses the operating system, including environment variables. Your scripts use os.environ.get() to read account IDs and bucket names without hardcoding them — a security best practice.",
        code: 'import os\n\n# Read environment variable — returns None if not set\naccount_id = os.environ.get("AWS_ACCOUNT_ID")\nbucket     = os.environ.get("TARGET_BUCKET")\n\n# From YOUR credential_theft.py:\nAWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID")\nif not AWS_ACCOUNT_ID:\n    print("[-] AWS_ACCOUNT_ID not set")\n    exit(1)',
      },
      {
        concept: "from X import Y — Importing Specific Things",
        plain: "Instead of importing an entire library, you can import just one specific thing from it. This is how your scripts import ClientError from botocore — so you can use it directly by name.",
        code: 'from botocore.exceptions import ClientError\n\n# Now use ClientError directly\ntry:\n    response = client.list_users()\nexcept ClientError as e:\n    error_code = e.response["Error"]["Code"]\n    print(f"AWS error: {error_code}")',
      },
      {
        concept: "from datetime import datetime, timezone",
        plain: "The datetime module handles dates and times. Your scripts stamp events with the current UTC time — the same format CloudTrail uses. datetime.now(timezone.utc) gives the current time in UTC.",
        code: 'from datetime import datetime, timezone\n\nnow = datetime.now(timezone.utc)\n\n# Format as CloudTrail-style timestamp\nformatted = now.strftime("%Y-%m-%dT%H:%M:%SZ")\nprint(formatted)   # 2026-03-16T03:00:00Z\n\n# From YOUR scripts — this exact line:\nprint(f"Time: {datetime.now(timezone.utc).strftime(\"%Y-%m-%dT%H:%M:%SZ\")}")',
      },
    ],
    codeContext: '# Top of every lab script\nimport boto3\nimport json\nimport os\nfrom botocore.exceptions import ClientError\nfrom datetime import datetime, timezone\n\n# Used together:\nAWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID")\nsession = boto3.Session(profile_name="lab-attacker")\nclient  = session.client("iam")\nnow     = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")',
    blanks: [
      {
        id: "b1", label: "Task 1 — Import the AWS SDK",
        prompt: "Load the boto3 library into your script.\n\n___ boto3",
        answers: ["import", "import boto3"],
        hint: "The keyword that loads a library.",
        explanation: "import boto3 loads the entire AWS SDK. Without it, any boto3.client() call crashes with NameError. Line 1 of every lab script.",
      },
      {
        id: "b2", label: "Task 2 — Read an environment variable",
        prompt: 'Read AWS_ACCOUNT_ID safely — return None if missing.\n\nAWS_ACCOUNT_ID = os.environ.___("AWS_ACCOUNT_ID")',
        answers: ["get", "get()"],
        hint: "Returns None if the key is missing instead of crashing.",
        explanation: "os.environ.get() is safe — it returns None if the variable isn't set. Your scripts then check for None and exit with an error message.",
      },
      {
        id: "b3", label: "Task 3 — Import one specific thing",
        prompt: "Import only ClientError from botocore.exceptions.\n\n___ botocore.exceptions ___ ClientError",
        answers: ["from botocore.exceptions import", "from ... import"],
        hint: "Pattern: from LIBRARY import SPECIFIC_THING",
        explanation: "from botocore.exceptions import ClientError loads just that one class. You can then write 'except ClientError' directly instead of 'except botocore.exceptions.ClientError'.",
      },
      {
        id: "b4", label: "Task 4 — Parse JSON into a dict",
        prompt: "Convert a raw CloudTrail JSON string into a Python dictionary.\n\nraw = '{\"eventName\": \"ListUsers\"}'\nevent = json.___( raw )",
        answers: ["loads(raw)", "loads"],
        hint: "loads = load string. Converts a JSON string into a dict.",
        explanation: "json.loads() converts a JSON string into a Python dictionary. CloudTrail log files on S3 are stored as JSON strings — this is how you turn them into dicts you can parse.",
      },
      {
        id: "b5", label: "Task 5 — Get current UTC time",
        prompt: "Get the current time in UTC — the timezone CloudTrail uses.\n\nnow = datetime.now( ___ )",
        answers: ["timezone.utc", "timezone.utc)"],
        hint: "Pass the UTC timezone object so the timestamp matches CloudTrail.",
        explanation: "datetime.now(timezone.utc) returns the current time in UTC. CloudTrail stores all event times in UTC — your scripts use this for timestamping and time-window detection.",
      },
    ],
    recap: [
      { concept: "import X", description: "Loads an entire library. import boto3 makes the full AWS SDK available." },
      { concept: "from X import Y", description: "Loads one specific thing. from botocore.exceptions import ClientError lets you use ClientError by name." },
      { concept: "boto3", description: "AWS SDK for Python. Used in every lab script for sessions, clients, and API calls." },
      { concept: "os.environ.get()", description: "Reads environment variables safely. Returns None if not set — never crashes." },
      { concept: "json.loads()", description: "Converts a JSON string into a Python dict. How you parse raw CloudTrail log files." },
      { concept: "datetime.now(timezone.utc)", description: "Current UTC timestamp. Matches CloudTrail's time format." },
    ],
  },

  {
    id: "m4",
    title: "Mission 4: Build Your First Detection Rule",
    subtitle: "Functions — Reusable Detection Logic",
    xpReward: 100,
    difficulty: "JUNIOR",
    diffColor: "#60a5fa",
    mitre: "T1078.004",
    briefing: "Three attack scenarios just landed in your queue. You need one detection function you can call on any event — not rewrite the same if/else every time. This is how all your lab scripts are structured.",
    teachingPoints: [
      {
        concept: "The Problem Functions Solve",
        plain: "So far you have written if/else logic directly in your script. That works for one event — but what if you need to check 50 events? You would copy and paste the same logic 50 times.\n\nA function is a named, reusable block of code. You write the logic once, give it a name, and then use that name to run it as many times as you need. Your entire lab is built this way — every phase in iam_enum.py and credential_theft.py is its own function.",
        code: '# Without functions — you copy this for every event\nif event1["eventName"] == "AssumeRole":\n    print("HIGH")\n\nif event2["eventName"] == "AssumeRole":\n    print("HIGH")\n\nif event3["eventName"] == "AssumeRole":\n    print("HIGH")\n\n# This does not scale. Functions fix this.',
      },
      {
        concept: "Defining a Function — def, Name, Parameters, Body",
        plain: "You create a function using the def keyword (short for define), followed by a name, parentheses, and a colon. The indented block beneath is the function body — the code that runs when you call the function.\n\nThe variable inside the parentheses is called a parameter. It is an input — a value you pass in when you call the function. Inside the body, that parameter works just like any other variable.",
        code: '# def keyword → name → (parameter) → colon\ndef greet(name):\n    print(f"Hello {name}")   # body — indented under def\n\n# Nothing happens yet — the function is just defined\n\n# Call it by name and pass in a value\ngreet("Greg")    # Hello Greg\ngreet("Alice")   # Hello Alice\n\n# The same value you pass in becomes the "name" variable inside',
      },
      {
        concept: "Return Values — Getting Data Back Out",
        plain: "A function can send data back to whoever called it using the return keyword. The moment Python hits return, the function stops and passes the value back.\n\nThe caller can store that value in a variable. This is how your privilege_escalation.py works — assume_privileged_role() returns credentials if the attack succeeds, or None if it fails. The caller checks which one it got.",
        code: 'def classify_risk(event_name):\n    if event_name == "AssumeRole":\n        return "HIGH"     # stop here, send "HIGH" back\n    if event_name == "ListUsers":\n        return "MEDIUM"   # stop here, send "MEDIUM" back\n    return "LOW"          # default — nothing matched\n\n# The caller captures the returned value\nrisk = classify_risk("AssumeRole")   # risk = "HIGH"\nrisk = classify_risk("ListBuckets")  # risk = "LOW"\n\nprint(risk)   # LOW',
      },
      {
        concept: "Returning a Dictionary — Multiple Values at Once",
        plain: "return can send back any value — including a dictionary. Instead of just returning a risk level string, you can return a dict containing the risk level, the reason, and the MITRE technique ID all at once.\n\nThe caller then accesses the individual fields using the bracket syntax you learned in Mission 1.",
        code: 'def analyze_event(event_name):\n    if event_name == "AssumeRole":\n        # Return a dictionary with multiple fields\n        return {\n            "risk":   "HIGH",\n            "reason": "Role assumption detected",\n            "mitre":  "T1078.004"\n        }\n    # Default return — also a dict\n    return {"risk": "LOW", "reason": "Normal", "mitre": "N/A"}\n\n# Call the function and store the returned dict\nresult = analyze_event("AssumeRole")\n\n# Access individual fields — same dict syntax as Mission 1\nprint(result["risk"])    # HIGH\nprint(result["mitre"])   # T1078.004',
      },
      {
        concept: ".get() — Safe Dictionary Access",
        plain: "When you use dict[\"key\"], Python crashes with a KeyError if that key does not exist. This is a real problem with CloudTrail logs — not every event has every field. An S3 event has a file key, but an STS event does not.\n\nThe .get() method is the safe alternative. You call it like a function on the dictionary, passing the key name and a default value. If the key exists, you get the value. If it does not exist, you get the default — no crash.",
        code: 'event = {"eventName": "AssumeRole"}\n\n# This CRASHES if "sourceIPAddress" is not in the dict\nip = event["sourceIPAddress"]    # KeyError!\n\n# .get() is safe — returns the default if key is missing\nip = event.get("sourceIPAddress", "unknown")   # "unknown"\n\n# Two arguments: the key name, then the default value\nevent_name = event.get("eventName", "")   # "AssumeRole"\nmissing    = event.get("fakeKey",    "")   # ""\n\n# From your lab scripts — this exact pattern is everywhere:\nevent_name = event.get("eventName", "")',
      },
    ],
    codeContext: 'SENSITIVE_KEYS = ["credentials", "secrets", "api-keys", "password", "token", "backup"]\n\n# Your task: complete this detection function\ndef analyze_event(event):\n    # Safely read the event name — default to "" if missing\n    event_name = event.get("eventName", "")\n\n    # Check for AssumeRole — privilege escalation\n    if event_name == "AssumeRole":\n        return {"risk": "HIGH", "reason": "Role assumption", "mitre": "T1078.004"}\n\n    # Check for enumeration calls\n    if event_name in ["ListUsers", "ListRoles", "ListBuckets"]:\n        return {"risk": "MEDIUM", "reason": "Enumeration", "mitre": "T1069.003"}\n\n    # Default\n    return {"risk": "LOW", "reason": "Normal activity", "mitre": "N/A"}',
    blanks: [
      {
        id: "b1", label: "Task 1 — Define the function",
        prompt: "Create a function called analyze_event that accepts one input called event.\n\n___ analyze_event(event):",
        answers: ["def", "def "],
        hint: "The keyword for creating a function. Three letters, short for 'define'.",
        explanation: "def analyze_event(event): tells Python: create a reusable block called analyze_event that accepts one input called event. Every function in your lab scripts starts with def — list_iam_users, assume_privileged_role, exfiltrate_data.",
      },
      {
        id: "b2", label: "Task 2 — Read a key safely with .get()",
        prompt: 'Read the eventName key safely. Use "" as the default if the key is missing.\n\nevent_name = event.___("eventName", "")',
        answers: ["get", "get()"],
        hint: ".get() takes two arguments: the key name, and a default value to return if the key is missing.",
        explanation: "event.get(\"eventName\", \"\") returns the event name if it exists, or an empty string if it doesn't — instead of crashing. Real CloudTrail logs can be inconsistent, so .get() is always safer than direct bracket access.",
      },
      {
        id: "b3", label: "Task 3 — Return data from the function",
        prompt: 'When AssumeRole is detected, send a HIGH risk result back to the caller.\n\nif event_name == "AssumeRole":\n    ___ {"risk": "HIGH", "reason": "Role assumption", "mitre": "T1078.004"}',
        answers: ["return"],
        hint: "The keyword that sends a value back to whoever called the function and immediately stops the function.",
        explanation: "return sends the dictionary back to the caller and exits the function immediately. No more lines in the function run after return. The caller gets a dict they can use: result[\"risk\"], result[\"mitre\"], etc.",
      },
      {
        id: "b4", label: "Task 4 — Return a string value inside a dict",
        prompt: 'Return a MEDIUM risk result for enumeration events.\n\nif event_name in ["ListUsers", "ListRoles", "ListBuckets"]:\n    return {"risk": ___, "reason": "Enumeration", "mitre": "T1069.003"}',
        answers: ['"MEDIUM"', "'MEDIUM'"],
        hint: "You are putting a text value into a dictionary. Text values (strings) always need quote marks around them.",
        explanation: '"MEDIUM" is a string — text that Python treats as a value, not code. It needs quotes. ListUsers, ListRoles, and ListBuckets are all recon calls your credential_theft.py makes during Phase 2 enumeration, all mapping to T1069.003.',
      },
    ],
    recap: [
      { concept: "def keyword", description: "Creates a reusable function. def analyze_event(event): defines a block that runs every time you call analyze_event(something)." },
      { concept: "Parameters", description: "The input variable inside the parentheses. When you call analyze_event(some_dict), Python puts that dict into the event variable for that call." },
      { concept: "return", description: "Sends a value back to the caller and immediately stops the function. The caller stores the result: risk = analyze_event(event)." },
      { concept: "Returning a dictionary", description: "Return a dict to send multiple values at once — risk, reason, MITRE ID. The caller accesses fields with result[\"risk\"] etc." },
      { concept: ".get()", description: "Safe dictionary access. event.get(\"key\", \"\") returns the default instead of crashing when a key is missing." },
    ],
  },

  {
    id: "m5",
    title: "Mission 5: The Attack Chain Analyzer",
    subtitle: "Classes — Building a Real Detection Tool",
    xpReward: 125,
    difficulty: "ENGINEER",
    diffColor: "#fbbf24",
    mitre: "T1552.005",
    briefing: "The full credential_theft.py chain just ran against your environment. You need a tool that can ingest multiple events one by one, remember every finding, and produce a final report. A single function can't do this — it forgets everything when it returns. You need a class.",
    teachingPoints: [
      {
        concept: "The Problem: Functions Forget Everything",
        plain: "When a function returns, all the variables inside it disappear. If you want to process 50 CloudTrail events and keep a running list of findings, you would have to pass that list into every function call and get it back out every time. That gets messy fast.\n\nWhat you really want is an object — something that holds data AND can perform actions on that data. That is what a class gives you.",
        code: '# The messy function approach — you must carry the list everywhere\ndef analyze(event, findings_list):\n    if event["eventName"] == "AssumeRole":\n        findings_list.append("HIGH: Role assumption")\n    return findings_list   # must return it back\n\nfindings = []                          # start with empty list\nfindings = analyze(event1, findings)   # pass in, get back\nfindings = analyze(event2, findings)   # pass in, get back again\nfindings = analyze(event3, findings)   # every single time\n\n# A class will eliminate all of this.',
      },
      {
        concept: "What a Class Is — A Blueprint for an Object",
        plain: "A class is a blueprint. From that blueprint, you can create objects — and each object has its own data and its own actions.\n\nThink of a class like a form template. The template defines what fields exist. Each time you fill out a new form, you get an independent copy with its own values.\n\nYou define a class with the class keyword, followed by a name and a colon. Everything indented beneath it belongs to the class.",
        code: '# Define the blueprint\nclass CloudTrailAnalyzer:\n    pass   # empty for now — just showing the structure\n\n# Create two separate objects from the same blueprint\nanalyzer1 = CloudTrailAnalyzer()\nanalyzer2 = CloudTrailAnalyzer()\n\n# They are completely independent — like two filled-out forms\n# Changes to analyzer1 do not affect analyzer2',
      },
      {
        concept: "__init__ — Setting Up a New Object",
        plain: "__init__ is a special method that Python calls automatically every time you create a new object from the class. This is where you set up the starting state — the data the object will remember.\n\nThe double underscores on each side mark it as a special Python method. You will also see self as the first parameter — we will explain that in the next slide.",
        code: 'class CloudTrailAnalyzer:\n\n    def __init__(self, analyst_name):\n        # This runs automatically when you create an object\n        # Set up starting data here\n        self.analyst_name = analyst_name\n        self.events   = []   # empty list — will grow\n        self.findings = []   # empty list — will grow\n\n# Creating the object automatically calls __init__\nanalyzer = CloudTrailAnalyzer("Greg")\n\n# The object now has these values stored on it\nprint(analyzer.analyst_name)   # Greg\nprint(analyzer.events)         # []',
      },
      {
        concept: "self — Each Object Refers to Itself",
        plain: "Every method in a class has self as its first parameter. self is how the object refers to itself — specifically to this object's own data.\n\nWhen you write self.findings, you mean THIS object's findings list. If you created two analyzers, each one has its own self.findings. They never share data.\n\nPython passes self automatically — you never type it when calling a method.",
        code: 'class CloudTrailAnalyzer:\n    def __init__(self, analyst_name):\n        self.analyst_name = analyst_name\n        self.findings = []\n\n# Create two objects — each gets its OWN data\nanalyzer1 = CloudTrailAnalyzer("Greg")\nanalyzer2 = CloudTrailAnalyzer("Alice")\n\n# Add a finding to analyzer1 only\nanalyzer1.findings.append("AssumeRole detected")\n\nprint(len(analyzer1.findings))   # 1\nprint(len(analyzer2.findings))   # 0 — completely separate\n\n# self.findings inside the class means\n# "the findings list belonging to whichever object called this"',
      },
      {
        concept: "Methods — Actions the Object Can Take",
        plain: "A method is just a function defined inside a class. The only difference is that the first parameter is always self — giving the method access to all the object's stored data.\n\nMethods can also call other methods on the same object using self. A leading underscore on a method name (like _analyze) is a convention meaning 'internal — do not call this from outside the class'.",
        code: 'class CloudTrailAnalyzer:\n    def __init__(self, analyst_name):\n        self.analyst_name = analyst_name\n        self.events   = []\n        self.findings = []\n\n    # Public method — called from outside\n    def ingest(self, event):\n        self.events.append(event)   # add to this object\'s list\n        self._analyze(event)         # call another method on self\n\n    # Internal method — called only from within the class\n    def _analyze(self, event):\n        name = event.get("eventName", "")\n        if name == "AssumeRole":\n            self.findings.append("HIGH: Role assumption")\n\n    # Report method — uses stored data\n    def report(self):\n        print(f"Analyst: {self.analyst_name}")\n        print(f"Events processed: {len(self.events)}")\n        print(f"Findings: {len(self.findings)}")',
      },
    ],
    codeContext: 'class CloudTrailAnalyzer:\n    def __init__(self, analyst_name):\n        self.analyst_name = analyst_name\n        self.events   = []\n        self.findings = []\n\n    def ingest(self, event):\n        self.events.append(event)\n        self._analyze(event)\n\n    def _analyze(self, event):\n        name = event.get("eventName", "")\n        if name == "AssumeRole":\n            self.findings.append("HIGH: Role assumption")\n\n    def report(self):\n        print(f"Analyst: {self.analyst_name}")\n        print(f"Findings: {len(self.findings)}")',
    blanks: [
      {
        id: "b1", label: "Task 1 — Start the class definition",
        prompt: "Define a class called CloudTrailAnalyzer.\n\n___ CloudTrailAnalyzer:",
        answers: ["class", "class "],
        hint: "The keyword for creating a class blueprint — just like def is for functions.",
        explanation: "class CloudTrailAnalyzer: creates the blueprint. Every time you write analyzer = CloudTrailAnalyzer(\"Greg\"), Python uses this blueprint to create a brand new independent object with its own data.",
      },
      {
        id: "b2", label: "Task 2 — Name the constructor method",
        prompt: "What is the special method Python calls automatically when you create a new object?\n\ndef ___(self, analyst_name):",
        answers: ["__init__"],
        hint: "It has two underscores on each side. Short for 'initialize'. Python calls it automatically — you never call it yourself.",
        explanation: "__init__ is the constructor. Python calls it automatically when you do CloudTrailAnalyzer(\"Greg\"). It is where you set up the object's starting state — empty lists, stored values — using self. so the data stays on the object.",
      },
      {
        id: "b3", label: "Task 3 — Store data on the object using self",
        prompt: "Inside __init__, store analyst_name on the object so every method can access it later.\n\n___ = analyst_name",
        answers: ["self.analyst_name"],
        hint: "To store something permanently on the object, put self. in front of the variable name.",
        explanation: "self.analyst_name = analyst_name stores the value on the object permanently. Without self., you would just have a local variable that disappears the moment __init__ finishes. The self. prefix is what makes data persist across method calls.",
      },
      {
        id: "b4", label: "Task 4 — Add an item to a list on the object",
        prompt: "Inside ingest(), add the incoming event to the object's events list.\n\nself.events.___(event)",
        answers: ["append(event)", "append"],
        hint: "This is the list method that adds one item to the end of the list. You used it in Mission 2.",
        explanation: "self.events.append(event) adds the event to this object's list. Every time ingest() is called, the list grows by one. After processing the full credential_theft.py attack chain, self.events holds all 6 API call dictionaries.",
      },
      {
        id: "b5", label: "Task 5 — Call another method on the same object",
        prompt: "Inside ingest(), after appending the event, call the _analyze method on this same object.\n\n___._analyze(event)",
        answers: ["self", "self."],
        hint: "To call another method that belongs to the same object, use the word that means 'this object'.",
        explanation: "self._analyze(event) tells Python: call the _analyze method on THIS object. The self. prefix is how methods on the same class talk to each other. Without self., Python would look for a standalone function called _analyze and crash.",
      },
    ],
    recap: [
      { concept: "class keyword", description: "Defines a blueprint. Each object created from it gets its own independent copy of all data." },
      { concept: "__init__", description: "The constructor — Python calls it automatically when you create an object. Set up starting state here with self. variables." },
      { concept: "self", description: "How the object refers to itself. self.findings means THIS object's findings list — not a global, not another object's." },
      { concept: "Methods", description: "Functions inside a class. They always have self as the first parameter, giving them access to the object's stored data." },
      { concept: ".append()", description: "Adds one item to the end of a list. self.events.append(event) grows the object's log with every ingest() call." },
      { concept: "State persistence", description: "self. variables survive between method calls. The object accumulates findings across every ingest() — unlike a function that forgets on return." },
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

function isCorrect(input, accepted) {
  const n = normalize(input);
  return accepted.some(a => normalize(a) === n);
}

const bg   = "#030712";
const surf = "#0f172a";
const bdr  = "#1e293b";
const tx   = "#f1f5f9";
const mute = "#64748b";
const acc  = "#22d3ee";
const gold = "#fbbf24";

// inject global reset to kill browser default body margin/padding
if (typeof document !== "undefined") {
  const s = document.createElement("style");
  s.textContent = "*, *::before, *::after { box-sizing: border-box; } html, body { margin: 0; padding: 0; background: #030712; }";
  document.head.appendChild(s);
}

const wrap  = { minHeight: "100vh", background: bg, color: tx, padding: 16, fontFamily: "monospace" };
const inner = { maxWidth: 580, margin: "0 auto" };
const card  = (extra = {}) => ({ background: surf, border: `1px solid ${bdr}`, borderRadius: 12, padding: 16, ...extra });
const pill  = (bg2, extra = {}) => ({ background: bg2, border: "none", color: "#fff", fontWeight: "bold", padding: "11px 16px", borderRadius: 10, cursor: "pointer", fontFamily: "monospace", fontSize: 14, width: "100%", ...extra });
const ghost = (extra = {}) => ({ background: "none", border: "none", color: mute, cursor: "pointer", fontSize: 13, fontFamily: "monospace", padding: 0, ...extra });

export default function App() {
  const SEED = { xp: 450, completed: ["m1","m2","m3","m4","m5"], history: { m1:{earned:75,correct:4,total:4}, m2:{earned:75,correct:4,total:4}, m3:{earned:75,correct:5,total:5}, m4:{earned:100,correct:4,total:4}, m5:{earned:125,correct:5,total:5} } };
  const saved = loadSave();
  const base  = (saved && saved.xp > 0) ? saved : SEED;

  const [xp,        setXp]        = useState(base.xp);
  const [completed, setCompleted] = useState(base.completed);
  const [history,   setHistory]   = useState(base.history);
  const [view,      setView]      = useState("hub");
  const [mission,   setMission]   = useState(null);
  const [teachIdx,  setTeachIdx]  = useState(0);
  const [answers,   setAnswers]   = useState({});
  const [hints,     setHints]     = useState({});
  const [graded,    setGraded]    = useState(null);
  const [flash,     setFlash]     = useState(false);

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ xp, completed, history })); } catch (_) {}
  }, [xp, completed, history]);

  const level     = LEVELS.reduce((b, l) => xp >= l.xpRequired ? l : b, LEVELS[0]);
  const nextLevel = LEVELS.find(l => l.xpRequired > xp) || null;
  const pct       = nextLevel ? Math.min(100, ((xp - level.xpRequired) / (nextLevel.xpRequired - level.xpRequired)) * 100) : 100;

  function go(m) { setMission(m); setTeachIdx(0); setAnswers({}); setHints({}); setGraded(null); setView("briefing"); }

  function submit() {
    const n    = mission.blanks.length;
    const base = Math.floor(mission.xpReward / n);
    const rem  = mission.xpReward - base * n;
    const worth = mission.blanks.map((_, i) => i === n - 1 ? base + rem : base);
    let earned  = 0;
    const results = mission.blanks.map((b, i) => {
      const ua      = (answers[b.id] || "").trim();
      const correct = isCorrect(ua, b.answers);
      const hinted  = !!hints[b.id];
      const bxp     = correct ? Math.max(0, worth[i] - (hinted ? 10 : 0)) : 0;
      earned += bxp;
      return { ...b, ua, correct, hinted, bxp, worth: worth[i] };
    });
    earned = Math.min(mission.xpReward, Math.max(0, earned));
    const ok = results.filter(r => r.correct).length;
    setGraded({ results, earned, ok, total: n });
    const prev  = history[mission.id]?.earned ?? 0;
    const delta = earned - prev;
    if (!completed.includes(mission.id)) {
      setXp(x => x + earned);
      setCompleted(c => [...c, mission.id]);
    } else if (delta !== 0) {
      setXp(x => Math.max(0, x + delta));
    }
    setHistory(h => ({ ...h, [mission.id]: { earned, correct: ok, total: n } }));
    setView("grade");
  }

  function save() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ xp, completed, history })); } catch (_) {}
    setFlash(true); setTimeout(() => setFlash(false), 2000);
  }

  function reset() {
    if (!window.confirm("Reset all progress?")) return;
    setXp(0); setCompleted([]); setHistory({});
    try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
    setView("hub");
  }

  // ── HUB ──────────────────────────────────────────────────────────────────
  if (view === "hub") return (
    <div style={wrap}>
      <div style={inner}>
        <div style={{ textAlign:"center", marginBottom:20 }}>
          <div style={{ fontSize:20, fontWeight:"bold", color:acc }}>☁️ CLOUD SECURITY PYTHON BOOTCAMP</div>
          <div style={{ fontSize:12, color:mute, marginTop:4 }}>cloud-attack-detection-lab edition</div>
        </div>

        <div style={{ display:"flex", justifyContent:"flex-end", gap:8, marginBottom:12 }}>
          <button onClick={save}  style={pill("#0891b2",{width:"auto",padding:"4px 12px",fontSize:11})}>{flash?"Saved!":"💾 Save"}</button>
          <button onClick={reset} style={pill("#7f1d1d",{width:"auto",padding:"4px 12px",fontSize:11})}>↺ Reset</button>
        </div>

        {/* Player card */}
        <div style={card({ borderColor:"#164e63", marginBottom:16 })}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:12 }}>
            <div>
              <div style={{ color:acc, fontWeight:"bold" }}>{level.badge} {level.title}</div>
              <div style={{ color:mute, fontSize:12 }}>Greg Lewis</div>
            </div>
            <div style={{ textAlign:"right" }}>
              <div style={{ color:gold, fontWeight:"bold", fontSize:20 }}>{xp} XP</div>
              <div style={{ color:"#475569", fontSize:11 }}>{completed.length}/{MISSIONS.length} missions</div>
            </div>
          </div>
          {nextLevel && <>
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:"#475569", marginBottom:4 }}>
              <span>→ {nextLevel.badge} {nextLevel.title}</span>
              <span>{nextLevel.xpRequired - xp} XP to go</span>
            </div>
            <div style={{ background:"#1e293b", borderRadius:4, height:6 }}>
              <div style={{ background:acc, borderRadius:4, height:6, width:`${pct}%`, transition:"width 0.5s" }} />
            </div>
          </>}
        </div>

        {/* Ranks */}
        <div style={card({ marginBottom:16 })}>
          <div style={{ color:mute, fontSize:11, textTransform:"uppercase", letterSpacing:2, marginBottom:8 }}>Ranks</div>
          {LEVELS.map(l => (
            <div key={l.id} style={{ display:"flex", alignItems:"center", gap:8, fontSize:12, color: xp>=l.xpRequired?"#67e8f9":"#334155", padding:"3px 0" }}>
              <span>{l.badge}</span><span style={{flex:1}}>{l.title}</span>
              <span>{l.xpRequired} XP</span>
              {xp >= l.xpRequired && <span style={{color:"#4ade80"}}>✓</span>}
            </div>
          ))}
        </div>

        {/* Missions */}
        <div style={{ color:mute, fontSize:11, textTransform:"uppercase", letterSpacing:2, marginBottom:8 }}>Missions</div>
        <div style={{ display:"flex", flexDirection:"column", gap:10, marginBottom:16 }}>
          {MISSIONS.map((m, i) => {
            const unlocked = i === 0 || completed.includes(MISSIONS[i-1].id);
            const done     = completed.includes(m.id);
            const hist     = history[m.id];
            return (
              <div key={m.id} onClick={() => unlocked && go(m)}
                style={{ ...card({ borderColor: done?"#14532d": unlocked?"#164e63":bdr, background: done?"#052e16":surf, opacity: unlocked?1:0.35, cursor: unlocked?"pointer":"default" }) }}>
                <div style={{ display:"flex", justifyContent:"space-between" }}>
                  <div style={{flex:1}}>
                    <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4, flexWrap:"wrap" }}>
                      <span style={{ fontSize:11, fontWeight:"bold", color:m.diffColor }}>{m.difficulty}</span>
                      <span style={{ fontSize:11, color:"#475569" }}>{m.mitre}</span>
                      {done && <span style={{ fontSize:11, color:"#4ade80" }}>✓ COMPLETE</span>}
                    </div>
                    <div style={{ fontWeight:"bold", color:tx, fontSize:14 }}>{m.title}</div>
                    <div style={{ color:mute, fontSize:12 }}>{m.subtitle}</div>
                    {done && hist && <div style={{ color:"#334155", fontSize:11, marginTop:4 }}>+{hist.earned} XP · {hist.correct}/{hist.total} correct</div>}
                  </div>
                  <div style={{ color:gold, fontWeight:"bold", fontSize:13, marginLeft:12 }}>+{m.xpReward}</div>
                </div>
                {!unlocked && <div style={{ color:"#334155", fontSize:11, marginTop:6 }}>🔒 Complete previous mission to unlock</div>}
              </div>
            );
          })}
        </div>

        {completed.length > 0 && (
          <button onClick={() => setView("results")} style={pill(surf, { border:`1px solid #164e63`, color:acc })}>📊 Full Results & Learning Summary</button>
        )}
      </div>
    </div>
  );

  // ── RESULTS ───────────────────────────────────────────────────────────────
  if (view === "results") {
    const done  = MISSIONS.filter(m => completed.includes(m.id));
    const totOk = Object.values(history).reduce((s,h)=>s+(h.correct||0),0);
    const totN  = Object.values(history).reduce((s,h)=>s+(h.total||0),0);
    return (
      <div style={wrap}><div style={inner}>
        <button onClick={()=>setView("hub")} style={ghost({marginBottom:16})}>← Hub</button>
        <div style={{textAlign:"center",marginBottom:20}}>
          <div style={{fontSize:20,fontWeight:"bold",color:acc}}>📊 Learning Results</div>
          <div style={{fontSize:12,color:mute}}>{level.badge} {level.title} · {xp} XP</div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:20}}>
          {[["Total XP",xp,gold],["Accuracy",totN>0?Math.round(totOk/totN*100)+"%":"0%","#4ade80"],["Missions",`${completed.length}/${MISSIONS.length}`,"#60a5fa"]].map(([l,v,c])=>(
            <div key={l} style={card({textAlign:"center"})}>
              <div style={{fontWeight:"bold",fontSize:18,color:c}}>{v}</div>
              <div style={{fontSize:11,color:mute}}>{l}</div>
            </div>
          ))}
        </div>
        {done.map(m => {
          const h = history[m.id];
          return (
            <div key={m.id} style={card({marginBottom:16})}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                <div style={{fontWeight:"bold",color:tx,fontSize:14}}>{m.title}</div>
                <div style={{color:gold,fontWeight:"bold"}}>+{h?.earned} XP</div>
              </div>
              <div style={{color:"#475569",fontSize:11,marginBottom:12}}>{h?.correct}/{h?.total} correct · MITRE {m.mitre}</div>
              <div style={{color:"#0891b2",fontSize:11,textTransform:"uppercase",letterSpacing:2,marginBottom:8}}>Concepts</div>
              {m.recap.map((r,i)=>(
                <div key={i} style={{borderLeft:"2px solid #164e63",paddingLeft:10,marginBottom:10}}>
                  <div style={{color:"#67e8f9",fontSize:12,fontWeight:"bold"}}>{r.concept}</div>
                  <div style={{color:mute,fontSize:11,lineHeight:1.6}}>{r.description}</div>
                </div>
              ))}
            </div>
          );
        })}
        <button onClick={()=>setView("hub")} style={pill("#0891b2")}>← Mission Hub</button>
      </div></div>
    );
  }

  // ── BRIEFING ──────────────────────────────────────────────────────────────
  if (view === "briefing" && mission) return (
    <div style={wrap}><div style={inner}>
      <button onClick={()=>setView("hub")} style={ghost({marginBottom:16})}>← Hub</button>
      <div style={{background:"#1a0000",border:"1px solid #7f1d1d",borderRadius:12,padding:16,marginBottom:16}}>
        <div style={{color:"#f87171",fontWeight:"bold",marginBottom:8}}>📡 INCOMING ALERT</div>
        <div style={{color:"#cbd5e1",fontSize:13,lineHeight:1.7}}>{mission.briefing}</div>
      </div>
      <div style={card({marginBottom:16})}>
        <div style={{color:acc,fontWeight:"bold",marginBottom:6}}>Objective</div>
        <div style={{color:"#94a3b8",fontSize:13}}>{mission.subtitle}</div>
        <div style={{display:"flex",gap:16,marginTop:8,fontSize:12}}>
          <span style={{color:gold}}>+{mission.xpReward} XP max</span>
          <span style={{color:"#475569"}}>MITRE {mission.mitre}</span>
          <span style={{color:"#475569"}}>{mission.blanks.length} questions</span>
        </div>
      </div>
      <button onClick={()=>setView("learn")} style={pill("#0891b2")}>Begin Training →</button>
    </div></div>
  );

  // ── LEARN ─────────────────────────────────────────────────────────────────
  if (view === "learn" && mission) {
    const tp     = mission.teachingPoints[teachIdx];
    const isLast = teachIdx === mission.teachingPoints.length - 1;
    return (
      <div style={wrap}><div style={inner}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
          <button onClick={()=>teachIdx===0?setView("briefing"):setTeachIdx(i=>i-1)} style={ghost()}>← Back</button>
          <span style={{color:mute,fontSize:12}}>Concept {teachIdx+1} / {mission.teachingPoints.length}</span>
        </div>
        <div style={{display:"flex",gap:4,marginBottom:16}}>
          {mission.teachingPoints.map((_,i)=>(
            <div key={i} style={{flex:1,height:4,borderRadius:2,background:i<=teachIdx?"#0891b2":"#1e293b"}}/>
          ))}
        </div>
        <div style={card({borderColor:"#164e63",marginBottom:16})}>
          <div style={{color:acc,fontWeight:"bold",fontSize:15,marginBottom:10}}>📖 {tp.concept}</div>
          <div style={{color:"#cbd5e1",fontSize:13,lineHeight:1.8,marginBottom:14,whiteSpace:"pre-wrap"}}>{tp.plain}</div>
          <div style={{background:"#020617",border:`1px solid ${bdr}`,borderRadius:8,padding:12}}>
            <div style={{color:mute,fontSize:11,marginBottom:6}}>EXAMPLE</div>
            <pre style={{color:"#86efac",fontSize:12,overflowX:"auto",whiteSpace:"pre-wrap",margin:0,lineHeight:1.7}}>{tp.code}</pre>
          </div>
        </div>
        <button onClick={()=>isLast?setView("challenge"):setTeachIdx(i=>i+1)} style={pill("#0891b2")}>
          {isLast?"Start Challenge →":"Next Concept →"}
        </button>
      </div></div>
    );
  }

  // ── CHALLENGE ─────────────────────────────────────────────────────────────
  if (view === "challenge" && mission) {
    const xpEach = Math.floor(mission.xpReward / mission.blanks.length);
    return (
      <div style={wrap}><div style={inner}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
          <button onClick={()=>setView("learn")} style={ghost()}>← Training</button>
          <span style={{color:gold,fontWeight:"bold",fontSize:13}}>+{mission.xpReward} XP available</span>
        </div>
        <div style={{background:"#020617",border:`1px solid ${bdr}`,borderRadius:12,padding:12,marginBottom:16}}>
          <div style={{color:mute,fontSize:11,marginBottom:6}}>CONTEXT — from your lab</div>
          <pre style={{color:"#86efac",fontSize:11,overflowX:"auto",whiteSpace:"pre-wrap",margin:0,lineHeight:1.7}}>{mission.codeContext}</pre>
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:12,marginBottom:16}}>
          {mission.blanks.map(b=>(
            <div key={b.id} style={card()}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
                <span style={{color:acc,fontSize:12,fontWeight:"bold"}}>{b.label}</span>
                <span style={{color:"#854d0e",fontSize:11}}>+{xpEach} XP</span>
              </div>
              <pre style={{color:"#94a3b8",fontSize:12,whiteSpace:"pre-wrap",marginBottom:10,lineHeight:1.7}}>{b.prompt}</pre>
              <input
                style={{width:"100%",background:"#020617",border:`1px solid #334155`,borderRadius:8,padding:"8px 12px",color:"#86efac",fontSize:13,fontFamily:"monospace",outline:"none",boxSizing:"border-box"}}
                placeholder="Type your answer..."
                value={answers[b.id]||""}
                onChange={e=>setAnswers(a=>({...a,[b.id]:e.target.value}))}
              />
              {!hints[b.id]
                ? <button onClick={()=>setHints(h=>({...h,[b.id]:true}))} style={ghost({color:"#713f12",fontSize:11,marginTop:6})}>💡 Show hint (-10 XP)</button>
                : <div style={{marginTop:8,background:"#1c1200",border:"1px solid #713f12",borderRadius:8,padding:"8px 12px",color:"#fde68a",fontSize:11}}>💡 {b.hint}</div>
              }
            </div>
          ))}
        </div>
        <button onClick={submit} style={pill("#15803d")}>Submit Answers →</button>
      </div></div>
    );
  }

  // ── GRADE ─────────────────────────────────────────────────────────────────
  if (view === "grade" && graded && mission) {
    const p  = Math.round(graded.ok / graded.total * 100);
    const sc = p===100?"#4ade80":p>=60?"#fbbf24":"#f87171";
    return (
      <div style={wrap}><div style={inner}>
        <div style={{textAlign:"center",marginBottom:20}}>
          <div style={{fontSize:36,marginBottom:4}}>{p===100?"🎯":p>=60?"📈":"📚"}</div>
          <div style={{fontSize:20,fontWeight:"bold",color:sc}}>{p===100?"Perfect Score!":p>=60?"Good Work!":"Keep Practicing!"}</div>
          <div style={{color:mute,fontSize:12,marginTop:4}}>{graded.ok}/{graded.total} correct · +{graded.earned}/{mission.xpReward} XP earned</div>
        </div>

        <div style={card({marginBottom:16})}>
          <div style={{display:"flex",justifyContent:"space-between",fontSize:11,color:mute,marginBottom:4}}>
            <span>Score</span><span>{p}%</span>
          </div>
          <div style={{background:"#1e293b",borderRadius:4,height:8,marginBottom:10}}>
            <div style={{background:sc,borderRadius:4,height:8,width:`${p}%`,transition:"width 0.5s"}}/>
          </div>
          <div style={{display:"flex",justifyContent:"space-between",fontSize:13}}>
            <span style={{color:"#94a3b8"}}>XP Earned</span>
            <span style={{color:gold,fontWeight:"bold"}}>+{graded.earned} / {mission.xpReward}</span>
          </div>
        </div>

        <div style={{color:mute,fontSize:11,textTransform:"uppercase",letterSpacing:2,marginBottom:8}}>Answer Review</div>
        <div style={{display:"flex",flexDirection:"column",gap:10,marginBottom:16}}>
          {graded.results.map(r=>(
            <div key={r.id} style={{background:r.correct?"#052e16":"#1a0000",border:`1px solid ${r.correct?"#14532d":"#7f1d1d"}`,borderRadius:12,padding:14}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <span style={{color:"#94a3b8",fontSize:12,fontWeight:"bold"}}>{r.label}</span>
                <div style={{display:"flex",gap:8,alignItems:"center"}}>
                  {r.hinted && <span style={{fontSize:10,color:"#713f12"}}>hint used</span>}
                  <span style={{fontSize:12,fontWeight:"bold",color:r.correct?"#4ade80":"#f87171"}}>
                    {r.correct?`✓ +${r.bxp} XP`:"✗ 0 XP"}
                  </span>
                </div>
              </div>
              <pre style={{color:mute,fontSize:11,whiteSpace:"pre-wrap",lineHeight:1.6,marginBottom:10}}>{r.prompt}</pre>
              <div style={{marginBottom:10}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                  <span style={{color:mute,fontSize:11,minWidth:72}}>You wrote:</span>
                  <code style={{fontSize:12,padding:"2px 8px",borderRadius:4,background:r.correct?"#14532d":"#7f1d1d",color:r.correct?"#86efac":"#fca5a5"}}>{r.ua||"(blank)"}</code>
                </div>
                {!r.correct && (
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{color:mute,fontSize:11,minWidth:72}}>Correct:</span>
                    <code style={{fontSize:12,padding:"2px 8px",borderRadius:4,background:"#14532d",color:"#86efac"}}>{r.answers[0]}</code>
                  </div>
                )}
              </div>
              <div style={{borderTop:`1px solid ${bdr}`,paddingTop:10}}>
                <div style={{color:"#0891b2",fontSize:11,fontWeight:"bold",marginBottom:4}}>Why this answer:</div>
                <div style={{color:mute,fontSize:11,lineHeight:1.7}}>{r.explanation}</div>
              </div>
            </div>
          ))}
        </div>

        <div style={card({marginBottom:16})}>
          <div style={{color:"#0891b2",fontSize:11,textTransform:"uppercase",letterSpacing:2,marginBottom:10}}>Concepts from this mission</div>
          {mission.recap.map((r,i)=>(
            <div key={i} style={{borderLeft:"2px solid #164e63",paddingLeft:10,marginBottom:10}}>
              <div style={{color:"#67e8f9",fontSize:12,fontWeight:"bold"}}>{r.concept}</div>
              <div style={{color:mute,fontSize:11,lineHeight:1.6}}>{r.description}</div>
            </div>
          ))}
        </div>

        <div style={{display:"flex",gap:10}}>
          <button onClick={()=>setView("results")} style={pill(surf,{flex:1,border:`1px solid ${bdr}`,color:"#94a3b8"})}>📊 Results</button>
          <button onClick={()=>setView("hub")}     style={pill("#0891b2",{flex:1})}>Mission Hub →</button>
        </div>
      </div></div>
    );
  }

  return (
    <div style={{...wrap,display:"flex",alignItems:"center",justifyContent:"center"}}>
      <div style={{textAlign:"center"}}>
        <div style={{fontSize:36,marginBottom:12}}>☁️</div>
        <div style={{color:acc,fontWeight:"bold",marginBottom:16}}>CLOUD SECURITY PYTHON BOOTCAMP</div>
        <button onClick={()=>setView("hub")} style={pill("#0891b2",{width:"auto",padding:"10px 24px"})}>Start →</button>
      </div>
    </div>
  );
}