var git = require('./git_node.js');
var utils = require('./release_utils.js');
var logger = require('./logger.js');

var repoName = "azure-c-shared-utility";
var repoUrl = "https://github.com/Azure/azure-c-shared-utility.git"
var releaserEmail = null;
var runOnlyStep = null;

utils.setSavedStateFile(process.env.temp + '/release_state' + repoName + '.txt');

var State = {
	UpdateMasterBranch: 10, // done
	UpdateDevelopBranch: 20, // done
	MergeMasterIntoDevelopBranch: 30, // done
	SnapToLatestSubmodules: 40,
	BumpVersions: 50,
	UpdateReleaseNotes: 60,
	MergeDevelopIntoMasterBranch: 65,
	ReleaseToMBED: 70,
	ReleaseNugetPackages: 80,
	ReleaseAptPackages: 90,
	ReleaseJavaPackages: 95,
	ReleaseNodePackages: 96,
	UpdateGitHubDocumentation: 99,
	Completed: 100 // done
}

function printUsage() {
	console.log("Usage:");
	console.log("node release.js email=someone@microsoft.com");
}

var failureOccured = false;

for (var i = 0; i < process.argv.length; i++) {
	if (process.argv[i].search(/^email=/) != -1) {
		releaserEmail = process.argv[i].substring(6, process.argv[i].length);
	}
	else if (process.argv[i].search(/^runOnlyStep=/) != -1) {
		runOnlyStep = process.argv[i].substring(12, process.argv[i].length);
	}
}

if (releaserEmail == null) {
	console.log("Failure: 'email' argument not provided.");
	failureOccured = true;
}


if (failureOccured == true) {
	console.log("");
	printUsage();
	process.exit(1);
}


logger.logInfo("Releasing the repo '" + repoName + "'");
logger.logInfo("Emails will be sent to: " + releaserEmail);
logger.logInfo("Validating current repo");

var status = git.status();
var remote_repos = git.getRemoteRepo();

if (status == null || 
	remote_repos.length == 0 || remote_repos['origin'] != repoUrl) {
	logger.logError("The release script must be executed from a valid clone of " + repoName + " repo.");
	failureOccured = true;
}
// else if (status.staged_files.length != 0 ||
	// status.untracked_files.length != 0 ||
	// status.unstaged_files.length != 0) {
	// logger.logError("Release cannot proceed on this repo as there are staged/unstaged/untracked files present.");
	// failureOccured = true;
// }

var currentState;
if (runOnlyStep != null)
{
	logger.logWarning("Running only step " + runOnlyStep);
	currentState = runOnlyStep;
}
else if ((currentState = utils.readSavedState()) == null) {
	currentState = State.UpdateMasterBranch;
}

logger.logWarning("Current state of the release is: " + currentState);

while (!failureOccured && currentState != State.Completed) {
	if (currentState == State.UpdateMasterBranch) {
		logger.logInfo("Updating local master branch");
		
		if (!git.checkout("master")) {
			logger.logError("Failed checking out master branch.");
			failureOccured = true;
		}
		else if (!git.pull("origin", "master")) {
			logger.logError("Failed pulling changed from origin/master.");
			failureOccured = true;
		}
		else if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.UpdateDevelopBranch;
		}
	}
	else if (currentState == State.UpdateDevelopBranch) {
		logger.logInfo("Updating local develop branch");
		
		if (!git.checkout("develop")) {
			logger.logError("Failed checking out develop branch.");
			failureOccured = true;
		}
		else if (!git.pull("origin", "develop")) {
			logger.logError("Failed pulling changed from origin/develop.");
			failureOccured = true;
		}
		else if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.MergeMasterIntoDevelopBranch;
		}
	}
	else if (currentState == State.MergeMasterIntoDevelopBranch) {
		logger.logInfo("Merging master branch into develop");
		
		if ((status = git.status()) == null) {
			logger.logError("Failed getting the git status. Cannot proceed.");
			failureOccured = true;
		}
		else if (status.head != "develop") {
			logger.logError("After fixing the merge conflicts the develop branch should be checked out. Cannot proceed");
			failureOccured = true;
		}
		else if (!git.merge("master")) {
			logger.logError("Failed merging master into develop.");
			failureOccured = true;
		}
		else if ((status = git.status()) == null) {
			logger.logError("Failed getting the repo status to verify the merge.");
			failureOccured = true;
		}
		else if (status.hasUnmergedPaths) {
			logger.logError("The merge is not clean. Please resolve the conflicts manually and re-run the release script.");
			failureOccured = true;
		}
		else if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.SnapToLatestSubmodules
		}
	}
	else if (currentState == State.SnapToLatestSubmodules) {
		logger.logInfo("Snapping to the latest submodules");
		
		var gitSubmodules = git.getSubmodulesStatus();
		var currentPath;
		
		for(var i = 0; i < gitSubmodules.length; i++) {
			process.chdir(gitSubmodules[i].path);
			
			if (git.checkout("develop")) {
				
			}
			
			process.chdir(currentPath);
		}
		
		process.chdir(currentPath);
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.BumpVersions;
		}
	}
	else if (currentState == State.BumpVersions) {
		logger.logInfo("Bumping versions on develop branch");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.UpdateReleaseNotes;
		}
	}
	else if (currentState == State.UpdateReleaseNotes) {
		logger.logInfo("Updating release notes");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.MergeDevelopIntoMasterBranch;
		}
	}
	else if (currentState == State.MergeDevelopIntoMasterBranch) {
		logger.logInfo("Merging develop branch back into master");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.ReleaseToMBED;
		}
	}

	else if (currentState == State.ReleaseToMBED) {
		logger.logInfo("Releasing to MBED");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.ReleaseNugetPackages;
		}
	}
	else if (currentState == State.ReleaseNugetPackages) {
		logger.logInfo("Releasing nuget packages");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.ReleaseAptPackages;
		}
	}
	else if (currentState == State.ReleaseAptPackages) {
		logger.logInfo("Releasing apt packages");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.ReleaseJavaPackages;
		}
	}
	else if (currentState == State.ReleaseJavaPackages) {
		logger.logInfo("Releasing Java packages");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.ReleaseNodePackages;
		}
	}
	else if (currentState == State.ReleaseNodePackages) {
		logger.logInfo("Releasing node packages");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.UpdateGitHubDocumentation;
		}
	}
	else if (currentState == State.UpdateGitHubDocumentation) {
		logger.logInfo("Updating GitHub documentation");
		
		if (runOnlyStep != null) {
			currentState = State.Completed;
		}
		else {
			currentState = State.Completed;
		}
	}
	else {
		logger.logError("The current state (" + currentState + ") is not recognized. Cannot proceed.");
		failureOccured = true;
	}
}

if (failureOccured) {
	logger.logError("Release failed. Please fix the issues and re-run it.");
	utils.saveState(currentState);
	process.exit(1);
} else {
	logger.logInfo("Release completed successfully");
	utils.clearSavedState();
	process.exit(0);
}}