var execSync = require('child_process').execSync;
var spawnSync = require('child_process').spawnSync;
var spawn = require('child_process').spawn;


var execSyncOptionsPipeAll = { stdio: 'pipe' };

function splitFileStateAndName(entry) {
	var stateNamePair = entry.split(/:[ ]+/);

	return { name: stateNamePair[1], state: stateNamePair[0] };
}

function gitGetStatus() {
	var result = null;
			
	var cmd = 'git status';
	var stdout = execSync(cmd).toString();
	
	if (stdout) {
		result = {
			head: null,
			staged_files: [],
			unstaged_files: [],
			untracked_files: [],
			hasUnmergedPaths: false,
			unmergedPaths: []
		};
	
		var parsingStaged = false;
		var parsingUnstagedChanges = false;
		var parsingUntrackedFiles = false;
		var parsingUnmergedPaths = false;
		var lines = stdout.split("\n");

		for(var i = 0; i < lines.length; i++) {
			if (lines[i].search(/^([ ]+\(use|^[ ]*no changes added to commit|^[ ]*nothing added to commit|^[ ]*$)/) != -1) {
				continue;
			}
			else if (lines[i].substring(0, 9) == "On branch") {
				result.head = lines[i].split(" ")[2];
			}
			else if (lines[i].search(/^[ ]*HEAD detached at/) != -1) {
				result.head = lines[i].split(" ")[3];
			}
			else if (lines[i].search(/^[ ]*Changes to be committed:/i) != -1) {
				parsingStaged = true;
				parsingUnstagedChanges = false;
				parsingUntrackedFiles = false;
				parsingUnmergedPaths = false;
			}
			else if (lines[i].search(/^[ ]*Changes not staged for commit:/i) != -1) {
				parsingStaged = false;
				parsingUnstagedChanges = true;
				parsingUntrackedFiles = false;
				parsingUnmergedPaths = false;
			}
			else if (lines[i].search(/^[ ]*Untracked files:/i) != -1) {
				parsingStaged = false;
				parsingUntrackedFiles = true;
				parsingUnstagedChanges = false;
				parsingUnmergedPaths = false;
			}
			else if (lines[i].search(/^[ ]*Unmerged paths:/) != -1) {
				parsingStaged = false;
				parsingUntrackedFiles = false;
				parsingUnstagedChanges = false;
				parsingUnmergedPaths = true;
			}
			else if (lines[i].search(/^[ ]*You have unmerged paths./) != -1) {
				result.hasUnmergedPaths = true;
			}
			else 
			{
				lines[i] = lines[i].replace(/^[\s\t]*/, "");
				
				if (parsingStaged) {
					result.staged_files.push(splitFileStateAndName(lines[i]));
				}
				else if (parsingUnstagedChanges) {
					result.unstaged_files.push(splitFileStateAndName(lines[i]));
				}
				else if (parsingUntrackedFiles) {
					result.untracked_files.push(lines[i]);
				}
				else if (parsingUnmergedPaths) {
					result.unmergedPaths.push(lines[i]);
				}
			}
		}
	}
	
	return result;
};

function gitGetRemoteRepo() {
	var result = {};
	
	try {
		var cmd = 'git remote -v';
		var stdout = execSync(cmd).toString();
		
		if (stdout) {
			var lines = stdout.split("\n");

			for(var i = 0; i < lines.length; i++) {
				if (lines[i].search(/^([ \t]*$)/) != -1) {
					continue;
				} else {
					var tokens = lines[i].split(/[ \t]/);
					
					result[tokens[0]] = tokens[1]; 
				}
			}
		}
	}
	catch (exception) {}
	
	return result;
}

function gitCheckout (branchName, create) {
	var result = false;
	
	if (branchName) {
		var cmd = 'git checkout '
		
		if (create == true) {
			cmd += '-b '
		}
			
		cmd += branchName;
	
		try {
			var stdout = execSync(cmd, execSyncOptionsPipeAll).toString();
			
			result = true;
		}
		catch (exception) {
			result = false;
		}
	}
	
	return result;
}

function gitMerge (branchName, ffOnly = false) {
	var result;
	
	var cmd = 'git merge ';
	if (ffOnly == true) {
		cmd += '-ff '
	}
	cmd += branchName;
	
	try {
		var stdout = execSync(cmd ).toString();

		if (stdout != null && (
			stdout.search(/Already up-to-date/) != -1)) {
			result = true;
		}
		else {
			result = false;
		}
	} catch (exception) {
		result = false;
	}
	
	return result;
}

function gitGetSubmodulesStatus(recursive) {
	var result = null;
	
	try {
		var cmd = 'git submodule status';
		if (recursive == true) {
			cmd += ' --recursive';
		}
		
		var stdout = execSync(cmd).toString();
		
		if (stdout != null && stdout != '') {
			result = [];
			
			var lines = stdout.split('\n');
			
			for(var i = 0; i<lines.length; i++) {
				var tokens = lines[i].split(" ");
				var submoduleInfo = null;
				
				if (tokens.length == 3) {
					submoduleInfo = {
						path: tokens[0].substring(1, tokens[0].length),
						head: tokens[1],
						isInitialized: (tokens[0].search(/^-/) == -1),
						headMatchesParentRepoIndex: (tokens[0].search(/^\+/) == -1),
						hasMergeConflicts: (tokens[0].search(/^U/) != -1)
					}
				} else if (tokens.length == 4) {
					submoduleInfo = {
						path: tokens[1],
						head: tokens[2],
						isInitialized: true,
						headMatchesParentRepoIndex: true,
						hasMergeConflicts: false
					}
				}
				
				if (submoduleInfo != null) {
					result.push(submoduleInfo);
				}
			}
		}
	}
	catch (exception) {
		console.log(exception);
		result = null;
	}
	
	return result;
}

function gitSubmoduleUpdate(recursive) {
	var cmd = 'git submodule update --init';
	
	if (recursive == true) {
		cmd += ' --recursive';
	}
	
	var stdout = execSync(cmd).toString();
	
	return (stdout != null);
}

function gitPull(repo, branch) {
	var result;
	
	var cmd = 'git pull';
	if (repo != null) {
		cmd += ' ' + repo;
		
		if (branch) {
			cmd += ' ' + branch;
		}
	}
	
	try {
		var stdout = execSync(cmd, execSyncOptionsPipeAll ).toString();
		
		result = 0;
	} catch (exception) {
		result = 1;
	}
	
	return (stdout != null);
}

exports.status = gitGetStatus;
exports.checkout = gitCheckout;
exports.getSubmodulesStatus = gitGetSubmodulesStatus;
exports.updateSubmodules = gitSubmoduleUpdate;
exports.merge = gitMerge;
exports.pull = gitPull;
exports.getRemoteRepo = gitGetRemoteRepo;
