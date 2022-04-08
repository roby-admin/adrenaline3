rule BITB_Phishing_JS_Detection {
	meta:
		description = "Detect key elements of a BITB framework based off the template GitHub JavaScript code"
		author = "@JCyberSec_"
		date = "21/03/2022"
		reference = "https://github.com/mrd0x/BITB"
	strings:
		// Detect colours used in the template
			$colours1 = "09765625" nocase
			$colours2 = "d6dae0" nocase
			$colours3 = "e81123" nocase

		// Detect variable names for key items
			$varNames1 = "minimize" nocase
			$varNames2 = "square" nocase
			$varNames3 = "exit" nocase
			$varNames4 = "titleBar" nocase

		// Detect unique variable names
			$uniqueVarNames1 = "draggable" nocase
			$uniqueVarNames2 = "ypos" nocase
			$uniqueVarNames3 = "pageY" nocase
			$uniqueVarNames4 = "xpos" nocase
			$uniqueVarNames5 = "pageX" nocase
			$uniqueVarNames6 = "dr" nocase

		// Detect HTML element names
			$htmlElements1 = "window" nocase
			$htmlElements2 = "title-bar-width" nocase
			$htmlElements3 = "content" nocase
			$htmlElements4 = "square" nocase
	condition:
		// Detect presence of all elements for strong confidence match
	 		all of ($colours*) and
	 		all of ($varNames*) and
	 		all of ($uniqueVarNames*) and
	 		all of ($htmlElements*)
}
