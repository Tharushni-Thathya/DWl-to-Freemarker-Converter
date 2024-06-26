import re

def identify_if_else_type(if_else_statement):
    # Check for Type 1: function call
    if re.search(r'\w+\(\)', if_else_statement):
        return "Type 1"
    
    # Check for Type 3: sessionVars
    elif re.search(r'sessionVars', if_else_statement):
        return "Type 3"
    
    # Check for nested if-else structure (Type 4)
    if_count = len(re.findall(r'if\s*\(', if_else_statement))
    else_count = len(re.findall(r'else', if_else_statement))
    if if_count > 1 or else_count > 1:
        # Check for Type 5: Multiple else if conditions
        elif_count = len(re.findall(r'else if\s*\(', if_else_statement))
        if elif_count >= 3:
            return "Type 5"
        return "Type 4"
    else:
        return "Type 2"


def extract_if_else(input_strs):
    pattern = re.compile(
        r'if\s*\([^)]*\)\s*(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^;]*;?)\s*else\s*(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^;]*;?)',
        re.DOTALL
    )
    
    results = []
    for input_str in input_strs:
        matches = pattern.findall(input_str)
        if matches:
            if_else_statement = matches[0].strip()
            results.append((if_else_statement, identify_if_else_type(if_else_statement)))
        else:
            results.append(("No if-else statement found", "Unknown"))
    
    return results

def process_type_1(if_else_statement):
    if_condition = re.search(r'if\s*\((.*?)\)\s*{', if_else_statement).group(1).strip()
    if_content_match = re.search(r'{(.*?)}\s*else', if_else_statement, re.DOTALL)
    if if_content_match:
        if_content = if_content_match.group(1).strip()
    else:
        if_content = "No content"
        
    else_content_match = re.search(r'else\s*{(.*?)}', if_else_statement, re.DOTALL)
    if else_content_match:
        else_content = else_content_match.group(1).strip()
    else:
        else_content = "null"
    
    return f"<#if {if_condition}>\n{if_content}\n<#else>{else_content}</#if>"

def process_type_2(if_else_statement):
    if_condition = re.search(r'if\s*\((.*?)\)\s*', if_else_statement).group(1).strip()
    if_content_match = re.search(r'\)\s*(.*?)\s*else', if_else_statement, re.DOTALL)
    if if_content_match:
        if_content = if_content_match.group(1).strip()
    else:
        if_content = "No content"
        
    else_content_match = re.search(r'else\s*(.*)', if_else_statement, re.DOTALL)
    if else_content_match:
        else_content = else_content_match.group(1).strip()
    else:
        else_content = "null"
    
    if_condition = re.sub(r'\$', 'value', if_condition)
    if_content = re.sub(r'\$', 'value', if_content)
    else_content = re.sub(r'\$', 'value', else_content)
    
    variables = re.findall(r'value\.(\w+)', if_condition)
    
    if variables:
        has_content_checks = " && ".join([f"(value.{variable}?has_content)" for variable in variables])
        if_condition_formatted = f"<#if ({if_condition})>"
    else:
        if_condition_formatted = f"<#if {if_condition}>"
    
    if_variables = re.findall(r'value\.(\w+)', if_content)
    if_content_formatted = if_content
    for var in if_variables:
        if_content_formatted = if_content_formatted.replace(f"value.{var}", f"<#if (value.{var}?has_content)>${{value.{var}}}<#else>null</#if>")
    
    if variables:
        main_variable = variables[0]
        main_variable_check = f"(value.{main_variable})?has_content"
    else:
        main_variable_check = "true"

    output = (f"<#if {main_variable_check}>\n"
              f"  {if_condition_formatted}\n"
              f"    {if_content_formatted}\n"
              f"  <#else>{else_content}</#if>\n"
              f"<#else>null</#if>")

    return output

def process_type_3(if_else_statement):
    if_condition_match = re.search(r'if\s*\((.*?)\)\s*', if_else_statement)
    if if_condition_match:
        if_condition = if_condition_match.group(1).strip()
    else:
        raise ValueError("Invalid if-else statement structure for Type 3.")

    if_content_match = re.search(r'\)\s*(.*?)\s*else', if_else_statement, re.DOTALL)
    if if_content_match:
        if_content = if_content_match.group(1).strip()
    else:
        raise ValueError("Invalid if-else statement structure for Type 3.")

    else_content_match = re.search(r'else\s*(.*)', if_else_statement, re.DOTALL)
    if else_content_match:
        else_content = else_content_match.group(1).strip()
    else:
        else_content = "null"

    if_variable_match = re.search(r'(\w+)\s*=', if_content)
    else_variable_match = re.search(r'(\w+)\s*=', else_content)

    if if_variable_match:
        if_variable = if_variable_match.group(1)
    else:
        if_variable = "content_variable"

    if else_variable_match:
        else_variable = else_variable_match.group(1)
    else:
        else_variable = "content_variable"

    field_path_match = re.search(r'sessionVars\.(\w+)', if_condition)
    if field_path_match:
        field_path = f"sessionVars.{field_path_match.group(1)}"
    else:
        field_path = "unknown_field"

    output = (
        f'<#assign {if_variable} = "">\n'
        f'<#if payload.{field_path}?exists>\n'
        f'  <#assign {if_variable} = payload.{field_path}>\n'
        f'<#else>\n'
        f'  <#assign {else_variable} = payload.{else_variable}>\n'
        f'</#if>\n'
        f'${{{if_variable}}},'
    )

    return output


def process_type_4(if_else_statement):
    ftl_output = []
    lines = if_else_statement.strip().splitlines()

    for line in lines:
        line = line.strip()
        
        if line.endswith("{"):
            continue  # Skip opening braces

        if line.startswith("if"):
            condition = re.search(r'\((.*?)\)', line[2:].strip()).group(1)
            if "contains" in condition:
                match = re.search(r'\((.*?)\)\s*contains\s*"([^"]+)"', condition)
                if match:
                    field_path, value = match.groups()
                    condition = f'({field_path.replace("*", "")})?seq_contains("{value}")'
            ftl_output.append(f'<#if {condition}>')
        elif line.startswith("else if"):
            condition = re.search(r'\((.*?)\)', line[7:].strip()).group(1)
            if "contains" in condition:
                match = re.search(r'\((.*?)\)\s*contains\s*"([^"]+)"', condition)
                if match:
                    field_path, value = match.groups()
                    condition = f'({field_path.replace("*", "")})?seq_contains("{value}")'
            ftl_output.append(f'<#elseif {condition}>')
        elif line.startswith("else"):
            ftl_output.append('<#else>')
        elif line.endswith("}"):
            ftl_output.append('</#if>')
        elif "!=" in line and "null" in line:
            match = re.search(r'\((.*?)\s*filter\s*\((.*?)\)\)\[(\d+)\]\.(\w+)', line)
            if match:
                field_path, filter_condition, index, field = match.groups()
                transformed_statement = f'"{field_path.replace("*", "")}?filter({filter_condition})[{index}].{field}"'
                ftl_output.append(f'    <#if {transformed_statement}?has_content>')
                ftl_output.append(f'        "${{{transformed_statement}}}"')
                ftl_output.append(f'    <#elseif {transformed_statement.replace("?has_content", "")}?has_content>')
                ftl_output.append(f'        "${{{transformed_statement.replace("?has_content", "")}}}"')
                ftl_output.append(f'    <#else>')
                ftl_output.append(f'        null')
                ftl_output.append(f'    </#if>')
        else:
            ftl_output.append(f'    {line}')  # Directly append non-conditional lines

    # Join all lines into a single string with proper formatting
    output = '\n'.join(ftl_output)

    # Print the formatted if-else statement
    return output


def process_type_5(if_else_statement):
    # Helper function to process conditions within if-else statements
    def process_conditions(dwl_code):
        # Replace "else if" with <#elseif>, then "if" with <#if>, and "else" with <#else>
        dwl_code = re.sub(r'\belse if\b', '<#elseif ', dwl_code)
        dwl_code = re.sub(r'\bif\b', '<#if ', dwl_code)
        dwl_code = re.sub(r'\belse\b', '<#else>', dwl_code)

        # Replace "!=" with ?has_content
        dwl_code = re.sub(r' != null', '?has_content', dwl_code)
        
        # Replace "and" with "&&"
        dwl_code = dwl_code.replace(' and ', ' && ')
        
        # Extract all variable paths and create a set of unique paths
        paths = re.findall(r'recipientParty\.Person\.\w+', dwl_code)
        unique_paths = sorted(set(paths), key=len, reverse=True)
        
        # Replace variable paths with ${variable paths}
        for path in unique_paths:
            dwl_code = dwl_code.replace(f'({path})', f'${{{path}}}')
        
        # Replace "++" with a space
        dwl_code = dwl_code.replace(' ++ ', ' ')
        
        # Remove unnecessary parentheses around strings
        dwl_code = re.sub(r'\(\s*"', '"', dwl_code)
        dwl_code = re.sub(r'"\s*\)', '"', dwl_code)
        
        # Close if and elseif tags properly
        dwl_code = re.sub(r'(<#if|<#elseif)\s*\(([^)]+)\)', r'\1 \2>', dwl_code)
        
        return dwl_code.strip()  # Remove trailing whitespace

    # Process the nested structure
    ftl_code = process_conditions(if_else_statement)
    
    # Ensure a final closing </#if> is added after the <#else>
    if '<#else>' in ftl_code and not ftl_code.strip().endswith('</#if>'):
        ftl_code += ' </#if>'
    
    # Remove quotes around empty string in <#else>
    output = ftl_code.replace('<#else> " "', '<#else> ')

    return output