
var LoggingLevel = {
	None: 0,
	Error: 1,
	Warning: 2,
	Info: 3
}

exports.LoggingLevel = LoggingLevel;
exports.currentLoggingLevel = LoggingLevel.Info;

function getTimeStamp() {
	var date = new Date();
	var stamp = date.getFullYear() + "/" + (date.getMonth() + 1) + "/" + date.getDate() + " " + date.getHours() + ":" + date.getMinutes() + ":" + date.getSeconds();
	return stamp;
}

function logInfo(message) {
	if (exports.currentLoggingLevel >= LoggingLevel.Info) {
		console.log(getTimeStamp() + " [INFO]: " + message);
	}
}

function logWarning(message) {
	if (exports.currentLoggingLevel >= LoggingLevel.Warning) {
		console.log(getTimeStamp() + " [WARN]: " + message);
	}
}

function logError(message) {
	if (exports.currentLoggingLevel >= LoggingLevel.Error) {
		console.log(getTimeStamp() + " [ERROR]: " + message);
	}
}

function setLoggingLevel(level) {
	if (level >= LoggingLevel.None && level <= LoggingLevel.Info) {
		exports.currentLoggingLevel = level;
	}
}

exports.logInfo = logInfo;
exports.logWarning = logWarning;
exports.logError = logError;
exports.setLoggingLevel = setLoggingLevel;