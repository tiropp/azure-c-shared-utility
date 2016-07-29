var fs = require('fs');

exports.savedStateFile = null;

function setSavedStateFile(filePath) {
	exports.savedStateFile = filePath;
}

function saveState(state) {
	fs.writeFileSync(exports.savedStateFile, state);
}

function readSavedState() {
	var savedState;
	
	try {
		savedState = fs.readFileSync(exports.savedStateFile);
	} catch (exception) {
		savedState = null;
	}
	
	return savedState;
}

function clearSavedState() {
	try {
		fs.unlinkSync(exports.savedStateFile);
	} catch (exception) { }
}

function fileExists(filePath) {
	var result;
	
	try {
		fs.accessSync(filePath);
		result = true;
	} catch (exception) {
		result = false;
	}
	
	return result;
}

exports.setSavedStateFile = setSavedStateFile;
exports.saveState = saveState;
exports.readSavedState = readSavedState;
exports.clearSavedState = clearSavedState;

exports.fileExists = fileExists;
