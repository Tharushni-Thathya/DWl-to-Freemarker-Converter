import React, { useState } from 'react'
import axios from 'axios';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { solarizedlight } from 'react-syntax-highlighter/dist/esm/styles/prism';
import './homePage.css'

const HomePage = () => {

    const [inputText, setInputText] = useState('');
    const [outputText, setOutputText] = useState('');

    const clearText = () => {
        setInputText('');
        setOutputText('');
    };

    const convertText = async () => {
        try {
            const response = await axios.post('http://localhost:5000/convert', { inputText });
            setOutputText(response.data.outputText);
        } catch (error) {
            console.error('Error converting text:', error);
        }
    };

    return (
        <div className='container'>
            <div className='head'>
                <h1>DWL to Freemarker Converter</h1>
            </div>
            <div className='middleContainer'>
                <div>
                    <h2>Input</h2>
                    <textarea className='leftTextArea' value={inputText}
                    onChange={(e) => setInputText(e.target.value)}></textarea>
                </div>
                <div>
                    <h2>Output</h2>
                    <div className='rightTextArea'>
                        <SyntaxHighlighter language="xml" style={solarizedlight}>
                            {outputText}
                        </SyntaxHighlighter>
                    </div>
                </div>
            </div>
            <div className='bottomContainer'>
                <button className='clearBtn' onClick={clearText}>Clear</button>
                <button className='convertBtn' onClick={convertText}>Convert</button>
            </div>

            
            
        </div>

        
    )
}

export default HomePage