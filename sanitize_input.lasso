<?lasso

/*
	'sanitize' type cleans up user input, like white space, and limits output to field size in database

	EXAMPLE

	1) Allows only apostrophes, hyphens and spaces in 'firstname' field:
		var(firstname = sanitize(string(web_request->param('fname')), -fieldtype='name'))

*/


define sanitize => type {
	data
		public input::string,
		public fieldtype::string,
		public output::string

	public onCreate(
		input::string, // Required parameter
		-fieldtype::string = string // Keyword optional parameter - 'match' fieldtype with 'case'
	) => {

		// Assign parameter values to data members
		.input = #input
		.fieldtype = #fieldtype

		// Remove all white space from start and end
		.input->trim

		// Replace any whitespace character (space, tab, carriage return, line feed, form feed) with a space
		local(inProcess = regexp(-find=`\s+`, -replace=` `, -input=.input)->replaceall)

		.output = regexp(-find=`<script.*?>`, -input=#inProcess)->replaceall // Removes javascript opening tag
		.output = regexp(-find=`<\/+script>`, -input=.output)->replaceall // Removes javascript ending tag

		match(.fieldtype) => {
		case('address')
			.output = regexp(-find=`[~!@$%^&*()_\+={}\[\]|:;\"<\,>?\/≤≥]`, -input=.output)->replaceall // Allow apostrophe, period, hyphen and # in address
			(.output->size > 60) ? .output = .output->substring(1, 60)
		case('city')
			.output = regexp(-find=`[~!@#$%^&*()_\+={}\[\]|:;\"<\,>\.?\/≤≥]`, -input=.output)->replaceall // Allow apostrophes, hyphens and spaces
			(.output->size > 30) ? .output = .output->substring(1, 30)
		case('email')
			.output = regexp(-find=`[~!#$%^&*()+={}\[\]|:;\"\'<\,>\?\/≤≥]`, -input=.output)->replaceall // Allow period, hyphen, underscore and @ in email
			(.output->size > 60) ? .output = .output->substring(1, 60)
		case('filename')
			.output = regexp(-find=`[~!@#$%^&*()+={}\[\]|:;\"\'<\,>\?\/≤≥]`, -input=.output)->replaceall // Allow period, hyphen and underscore
		case('html')
			.output = regexp(-find=`[|]`, -input=.output)->replaceall
		case('name')
			.output = regexp(-find=`[~!@#$%^&*()_\+={}\[\]|:;\"<\,>\.?\/≤≥]`, -input=.output)->replaceall // Allow apostrophes, hyphens and spaces
			(.output->size > 30) ? .output = .output->substring(1, 30)
		case('nojavascript')
			.output = .output->asCopy // Just trims the user input and removes any javascript
		case('phone')
			.output = regexp(-find=`\D+`, -input=.output)->replaceall // Allow only digits
			(.output->size > 10) ? .output = .output->substring(1, 10)
		case('phoneext')
			.output = regexp(-find=`\D+`, -input=.output)->replaceall // Allow only digits
			(.output->size > 4) ? .output = .output->substring(1, 4)
		case('postalcode')
			.output = regexp(-find=`[~!#$%^&*()+={}\[\]|:;\"\'<\,>\?\/≤≥ ]`, -input=.output)->replaceall // Replace all including spaces
			(.output->size > 7) ? .output = .output->substring(1, 7)
		case('password')
			(.output->size > 30) ? .output = .output->substring(1, 30)
		case('username')
			(.output->size > 60) ? .output = .output->substring(1, 60)
		case
			.output = regexp(-find=`[~!@#$%^&*()_\-+={}\[\]|:;\"\'<\,>\.?\/≤≥]`, -input=.output)->replaceall // Replace all except spaces
		}

		return .output
	}
}

?>