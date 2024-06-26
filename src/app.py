# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from if_else_converter import extract_if_else, process_type_1, process_type_2, process_type_3,process_type_4,process_type_5
from for_loop_converter import extract_for, process_type_A, process_type_B, process_type_C, process_type_D, process_type_E,process_type_F,process_type_G
from text_value_converter import process_input

app = Flask(__name__)
CORS(app)

@app.route('/convert', methods=['POST'])
def convert():
    data = request.get_json()
    input_text = data.get('inputText', '')

    result = ""

    # Check for keywords in the input text
    if 'if' in input_text:
        if_else_statements = extract_if_else([input_text])
        for statement, type_ in if_else_statements:
            if type_ == "Type 1":
                result += process_type_1(statement)
            elif type_ == "Type 2":
                result += process_type_2(statement)
            elif type_ == "Type 3":
                result += process_type_3(statement)
            elif type_ == "Type 4":
                result += process_type_4(statement) 
            elif type_ == "Type 5":
                result += process_type_5(statement)    
       
    if 'for' in input_text or 'map' in input_text:
        for_statements = extract_for([input_text])
        for statement in for_statements:
            if statement[1] == "Type A":
                result += process_type_A(statement[2])
            elif statement[1] == "Type B":
                result += process_type_B(statement[2])
            elif statement[1] == "Type C":
                result += process_type_C(statement[2])
            elif statement[1] == "Type D":
                result += process_type_D(statement[2])
            elif statement[1] == "Type E":
                result += process_type_E(statement[2])
            elif statement[1] == "Type F":
                result += process_type_F(statement[2])
            elif statement[1] == "Type G":
                result += process_type_G(statement[2]) 


    strings_to_check = ["if", "for", "map"]

# Check if none of the strings are in the input text
    if all(s not in input_text for s in strings_to_check):            
         result = process_input(input_text)
    
    return jsonify({"outputText": result})

if __name__ == '__main__':
    app.run(debug=True)
