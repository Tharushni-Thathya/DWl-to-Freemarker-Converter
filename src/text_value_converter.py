import re

def texthandle(input_string):
    
    # Regex to find field names without quotes before a colon
    pattern = re.compile(r'(?<!")(\b\w+\b)(?=\s*:)')
    
    # Replace the matches with the field name in quotes
    formatted_string = pattern.sub(r'"\1"', input_string)
    
    return formatted_string

def value_handling(input_string):
    # Regex to find the field name and its path
    pattern = re.compile(r'(\w+):\s*trim\((.*?)\)')
    
    def replacer(match):
        field_name = match.group(1)
        field_path = match.group(2)
        return f'"{field_name}": <#if ({field_path})?has_content>"${{{field_path}?trim}}"<#else>null</#if>'
    
    # Apply the replacement
    formatted_string = pattern.sub(replacer, input_string)
    
    return formatted_string

def process_input(input_string):
    # Check for the pattern where a field name has a value with inverted commas
    pattern = re.compile(r'\w+:\s*"[^"]*"')
    if pattern.search(input_string):
        output_string = texthandle(input_string)
    else:
        output_string = value_handling(input_string)
    
    return output_string
