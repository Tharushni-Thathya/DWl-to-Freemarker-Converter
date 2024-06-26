import re

def identify_for_type(for_statement):
    if re.search(r'map\s*\(\s*value\s*,\s*index\s*\)', for_statement):
        return "Type A"
    elif re.search(r'map\s+using\s*\(.*?=\s*\$.*?splitBy\s*["\']', for_statement):
        return "Type B"
    elif re.search(r'map\s*\(\(\s*parent\s*,\s*parentindex\s*\)', for_statement):
        return "Type C"
    elif re.search(r'map\s*\(\s*item\s*,\s*index\s*\)', for_statement):
        return "Type D"
    elif re.search(r'map\s*\(\s*outerItem\s*,\s*outerIndex\s*\)', for_statement):
        return "Type E"
    elif re.search(r'map\s*\(\s*(?:record|item)\s*,\s*(?:index|idx)\s*\)', for_statement):
        return "Type F"
    elif re.search(r'map\s*\(\s*element\s*,\s*index\s*\)', for_statement):
        return "Type G"
    else:
        return "Unknown"

def extract_for(input_strs):
    pattern = re.compile(
        r'map\s*\((?:[^{}]|\{[^{}]*\})*\)|map\s+using\s*\(.*?\)|map\s*\(\(\s*parent\s*,\s*parentindex\s*\)|map\s*\(\s*item\s*,\s*index\s*\)|map\s*\(\s*outerItem\s*,\s*outerIndex\s*\)|map\s*\(\s*record\s*,\s*index\s*\)',
        re.DOTALL
    )
    
    results = []
    for input_str in input_strs:
        matches = pattern.findall(input_str)
        if matches:
            for_statement = matches[0].strip()
            results.append((for_statement, identify_for_type(for_statement), input_str))
        else:
            results.append(("No for statement found", "Unknown", input_str))
    
    return results


def process_type_A(for_statement):
    def transform_column_condition(condition):
        condition = re.sub(r'if\s*\(\((value\.\w+)\s*!=\s*null\)\s*and\s*\(not\s*\(\1\s*contains\s*"N/A"\)\)\)',
                           r'\1?has_content && \1?contains("N/A") == false', condition)
        return condition

    path_pattern = re.compile(r'(\S+)\s*!=\s*null')
    map_pattern = re.compile(r'map\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*->\s*\{(.*?)\}', re.DOTALL)

    path_match = path_pattern.search(for_statement)
    map_match = map_pattern.search(for_statement)

    if path_match and map_match:
        path = path_match.group(1).replace('.*', '.TABLE').replace('.', '.')
        map_var = map_match.group(1)
        map_block = map_match.group(2).strip()

        columns = []
        for line in map_block.split('\n'):
            if ':' not in line:
                continue
            col_name, condition = line.split(':', 1)
            col_name = col_name.strip()
            condition = condition.strip().rstrip(',')

            field_name_match = re.search(r'value\.(\w+)', condition)
            field_name = field_name_match.group(1) if field_name_match else col_name

            ftl_condition = transform_column_condition(condition)

            transformation_function = ''
            transformation_match = re.search(r'(\w+)\(.*?trim\(value\.(.*?)\)', condition)
            if transformation_match:
                transformation_function = transformation_match.group(1)
                field_name = transformation_match.group(2)

            if transformation_function:
                output_value = f'${{{transformation_function}(value.{field_name}?trim?number / 100)}}'
            else:
                output_value = f'${{value.{field_name}?trim}}'
            
            if_statement = f'<#if ({ftl_condition})>'
            col_line = f'    "{col_name}": {if_statement}"{output_value}"<#else>null</#if>'
            columns.append(col_line)

        ftl_columns = ',\n'.join(columns)

        final_output = f"""
            <#if {path}?has_content>
                <#list {path} as {map_var}>
                {{
                    {ftl_columns}
                }}<#if {map_var}?has_next>,</#if>
                </#list>
            <#else>null</#if>
            """
        return final_output.strip()
    return "No valid Type A for statement found"

def process_type_B(for_statement):
    def extract_attributes(attribute_str):
        attributes = re.findall(r'(\w+)\s*:\s*([^\s,]+)', attribute_str)
        return attributes

    # Patterns to extract necessary parts
    user_access_pattern = re.compile(r'(\w+)\s*@(.*?):')
    path_pattern = re.compile(r'using\s*\((.*?)\s*=\s*\$.*?splitBy\s*["\']')
    map_pattern = re.compile(r'\s*map\s+using\s*\(.*?\)\s*\{(.*)\}', re.DOTALL)

    # Matching and extracting parts
    user_access_match = user_access_pattern.search(for_statement)
    path_match = path_pattern.search(for_statement)
    map_match = map_pattern.search(for_statement)

    if user_access_match and path_match and map_match:
        user_access = user_access_match.group(1)
        attributes = extract_attributes(user_access_match.group(2).strip())
        attribute_str_formatted = " ".join([f'{key}="${{payload.{value.replace("flowVars.", "")}!""}}" ' for key, value in attributes])

        path = path_match.group(1).strip()
        map_block = map_match.group(1).strip()

        # Extracting FIDs keyword
        fids_pattern = re.compile(r'(\w+)\s*:')
        fids_match = fids_pattern.search(map_block)
        if (fids_match):
            fids = fids_match.group(1)
        else:
            fids = "FIDs"

        # Extract columns
        columns = []
        for line in map_block.split('\n'):
            if ':' not in line:
                continue
            col_name, content = line.split(':', 1)
            col_name = col_name.strip()
            content = content.strip().rstrip(',')
            columns.append((col_name, content))

        ftl_columns = "\n".join([f'            <{col[0]}>{content}</{col[0]}>' for col in columns])

        final_output = f"""
<#assign items = payload.{path}?split('+')>
<{user_access} {attribute_str_formatted.strip()}>
<#list items as item>
    <#assign record = item?split(',')>
    <{fids}>
{ftl_columns}
    </{fids}>
</#list>
</{user_access}>
"""
        return final_output.strip()
    return "No valid Type B for statement found"

def process_type_C(for_statement):
    path_pattern = re.compile(r'(\w+\.\w+\.\w+)\s*map\s*\(\(\s*parent\s*,\s*parentindex\s*\)')
    parent_var_pattern = re.compile(r'(\w+): parent\.(\w+)')
    main_object_pattern = re.compile(r'(\w+):\s*\{\s*(\w+):')

    path_match = path_pattern.search(for_statement)
    parent_var_match = parent_var_pattern.search(for_statement)
    main_object_match = main_object_pattern.search(for_statement)

    if path_match and parent_var_match and main_object_match:
        path = path_match.group(1)
        parent_var = parent_var_match.group(1)
        field_name = parent_var_match.group(2)
        main_object = main_object_match.group(1)
        roles_field = main_object_match.group(2)

        final_output = f"""
"{main_object}": {{
    "{roles_field}": 
        <#list payload.{path} as value>
        <#if value?exists>
        {{
            {parent_var}: ${{value.{field_name}}}
        }}<#if value?has_next>,</#if>
        </#if>
        </#list>
}},
"""
        return final_output.strip()
    return "No valid Type C for statement found"

def process_type_D(for_statement):
    # Pattern to extract the path
    path_pattern = re.compile(r'(\S+)\s*!=\s*null')
    # Pattern to extract the map block
    map_pattern = re.compile(r'map\s*\(\s*item\s*,\s*index\s*\)\s*->\s*\{(.*?)\}', re.DOTALL)

    # Finding the matches for path and map block
    path_match = path_pattern.search(for_statement)
    map_match = map_pattern.search(for_statement)

    if path_match and map_match:
        # Extract the path and map block
        path = path_match.group(1).replace('payload.', '')
        map_block = map_match.group(1).strip()

        columns = []
        # Iterate through each line in the map block
        for line in map_block.split('\n'):
            if ':' not in line:
                continue
            col_name, condition = line.split(':', 1)
            col_name = col_name.strip()
            condition = condition.strip().rstrip(',')

            # Extract the condition without the 'if' and 'else null' parts
            ftl_condition = re.sub(r'if\s*\((.*?)\)\s*else\s*null', r'\1', condition).strip()
            ftl_condition = ftl_condition.replace("and", "&&").replace("or", "||")

            # Check for customFunction usage
            if 'customFunction' in condition:
                condition = re.sub(r'customFunction\((.*?)\)', r'\1', condition)
                if_statement = f'<#if item.{col_name}?has_content>"${{customFunction(item.{col_name}?trim)}}"<#else>null</#if>'
            else:
                if_statement = f'<#if item.{col_name}?has_content>"${{item.{col_name}?trim}}"<#else>null</#if>'
            
            columns.append(f'        "{col_name}": {if_statement}')

        ftl_columns = ',\n'.join(columns)

        final_output = f"""
<#if payload.{path}?has_content>
    <#list payload.{path} as item>
    {{
{ftl_columns}
    }}<#if item?has_next>,</#if>
    </#list>
<#else>null</#if>
"""
        return final_output.strip()
    return "No valid Type D for statement found"

def process_type_E(for_statement):
    # Define patterns for path and map block
    path_pattern = re.compile(r'(\S+)\s*!=\s*null')
    map_pattern = re.compile(r'map\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*->\s*\{(.*?)\}', re.DOTALL)
    inner_map_pattern = re.compile(r'(\w+)\s*=\s*\1\.(\w+)\s*map\s*\((\w+)\s*,\s*\w+\)\s*->\s*\{(.*?)\}', re.DOTALL)

    # Find path and map block in the for_statement
    path_match = path_pattern.search(for_statement)
    map_match = map_pattern.search(for_statement)

    if path_match and map_match:
        # Extract path and map block content
        path = path_match.group(1)
        outer_item_name = map_match.group(1)
        inner_item_name = map_match.group(2)
        map_block = map_match.group(3).strip()

        outer_columns = []
        inner_columns = []

        # Process inner mappings
        inner_matches = inner_map_pattern.findall(map_block)
        for match in inner_matches:
            inner_var, outer_field, inner_item, inner_block = match
            inner_block = inner_block.strip()
            inner_lines = []

            # Process inner block lines
            for inner_line in inner_block.split('\n'):
                inner_line = inner_line.strip()
                if not inner_line or ':' not in inner_line:
                    continue
                col_name, condition = inner_line.split(':', 1)
                col_name = col_name.strip()
                condition = condition.strip().rstrip(',')

                # Generate FTL condition
                ftl_condition = re.sub(r'if\s*\((.*?)\)', r'\1', condition)
                if_statement = f'<#if ({ftl_condition})>'
                inner_lines.append(f'            "{col_name}": {if_statement}"${{{inner_item}.{col_name}?trim}}\"<#else>null</#if>')

            inner_columns.append('\n'.join(inner_lines))

        # Process outer mappings
        for line in map_block.split('\n'):
            line = line.strip()
            if not line or '=' in line:
                continue
            col_name, condition = line.split(':', 1)
            col_name = col_name.strip()
            condition = condition.strip().rstrip(',')

            # Generate FTL condition
            ftl_condition = re.sub(r'if\s*\((.*?)\)', r'\1', condition)
            if_statement = f'<#if ({ftl_condition})>'
            outer_columns.append(f'        "{col_name}": {if_statement}"${{{outer_item_name}.{col_name}?trim}}\"<#else>null</#if>')

        # Join columns into FTL format strings
        ftl_outer_columns = ',\n'.join(outer_columns)
        ftl_inner_columns = ',\n'.join(inner_columns)

        # Construct final FTL output
        final_output = f"""
<#if {path}?has_content>
    <#list {outer_item_name} as {outer_item_name}>
    {{
        {ftl_outer_columns},
        "innerItems": <#if {outer_item_name}.{inner_item_name}?has_content>
            <#list {outer_item_name}.{inner_item_name} as {inner_item_name}>
            {{
{ftl_inner_columns}
            }}<#if {inner_item_name}?has_next>,</#if>
            </#list>
        <#else>null</#if>
    }}<#if {outer_item_name}?has_next>,</#if>
    </#list>
<#else>null</#if>
"""
        return final_output.strip()

    return "No valid Type E for statement found"

def process_type_F(for_statement):
    # Define patterns for path and map block
    path_pattern = re.compile(r'(\S+)\s*!=\s*null')
    map_pattern = re.compile(r'map\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*->\s*\{(.*?)\}', re.DOTALL)

    # Find path and map block in the for_statement
    path_match = path_pattern.search(for_statement)
    map_match = map_pattern.search(for_statement)

    if path_match and map_match:
        # Extract path and map block content
        path = path_match.group(1).replace('payload.', '')
        outer_item_name = map_match.group(1)
        inner_item_name = map_match.group(2)
        map_block = map_match.group(3).strip()

        columns = []

        # Process each line in the map block
        for line in map_block.split('\n'):
            line = line.strip()
            if ':' not in line:
                continue
            col_name, condition = line.split(':', 1)
            col_name = col_name.strip()
            condition = condition.strip().rstrip(',')

            # Generate FTL condition
            ftl_condition = re.sub(r'if\s*\((.*?)\)\s*else\s*null', r'\1', condition)
            ftl_condition = ftl_condition.replace("and", "&&").replace("or", "||")
            if_statement = f'<#if {ftl_condition}>'
            columns.append(f'        "{col_name}": {if_statement}"${{{outer_item_name}.{col_name}?trim}}"<#else>null</#if>')

        # Generate accumulation FTL block dynamically
        accumulate_block = ""
        for line in map_block.split('\n'):
            line = line.strip()
            if 'accumulate' in line:
                # Extract the accumulation function dynamically
                accumulate_function = re.search(r'accumulate\((.*?)\)', line).group(1).strip()
                accumulate_expression = accumulate_function.split(',')[0].strip()
                accumulate_initial_value = accumulate_function.split(',')[1].strip()

                # Extract the variable names dynamically
                variable_names = re.findall(r'\w+', accumulate_expression)
                sum_variable = variable_names[0]  # Assuming the first variable is the sum

                accumulate_block += f"""
        <#assign {sum_variable} = {accumulate_initial_value}>
        <#list payload.{path} as i>
            <#assign {sum_variable} = {accumulate_expression}>
        </#list>
                """

        ftl_columns = ',\n'.join(columns)

        final_output = f"""
<#if payload.{path}?has_content>
    <#list payload.{path} as {outer_item_name}>
    {{
{ftl_columns},
        "cumulativeSum": 
        {accumulate_block}
        ${{{{ {sum_variable} }}}}
    }}<#if {outer_item_name}_has_next>,</#if>
    </#list>
<#else>null</#if>
"""
        return final_output.strip()

    return "No valid Type F for statement found"

def process_type_G(for_statement):
    path_pattern = re.compile(r'(\S+)\s*!=\s*null')
    map_pattern = re.compile(r'map\s*\(\s*element\s*,\s*index\s*\)\s*->\s*\{(.*?)\}', re.DOTALL)

    path_match = path_pattern.search(for_statement)
    map_match = map_pattern.search(for_statement)

    if path_match and map_match:
        path = path_match.group(1).replace('payload.', '')
        map_block = map_match.group(1).strip()

        columns = []
        for line in map_block.split('\n'):
            if ':' not in line:
                continue
            col_name, condition = line.split(':', 1)
            col_name = col_name.strip()
            condition = condition.strip().rstrip(',')

            # Transform conditions from DSL to FTL
            ftl_condition = re.sub(r'if\s*\((.*?)\)\s*else\s*null', r'\1', condition)
            ftl_condition = ftl_condition.replace("and", "&&").replace("or", "||")
            ftl_condition = ftl_condition.replace("!= null", "?has_content")

            # Build the FTL if-else statements
            if_statement = f'<#if {ftl_condition}>'
            columns.append(f'        "{col_name}": {if_statement}"${{element.{col_name}}}"<#else>null</#if>')

        ftl_columns = ',\n'.join(columns)

        final_output = f"""
<#if payload.{path}?has_content>
    <#list payload.{path} as element>
    {{
{ftl_columns}
    }}<#if element_has_next>,</#if>
    </#list>
<#else>null</#if>
"""
        return final_output.strip()
    return "No valid Type G for statement found"