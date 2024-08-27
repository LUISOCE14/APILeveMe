import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function loadCensorWords() {
    try {
        const wordsPath = resolve(__dirname, 'censorWords.json');
        const wordsJson = fs.readFileSync(wordsPath, 'utf8');
        const wordsObject = JSON.parse(wordsJson);
        return wordsObject.words;
    } catch (error) {
        console.error(`Error loading censor words:`, error);
        return [];
    }
}

function containsCensoredWords(text, words) {
    const normalizedText = text.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
    
    for (let word of words) {
        const normalizedWord = word.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
        
        // Crear un patrón que permita variaciones de letras
        const patternString = normalizedWord.split('').map(char => {
            switch(char) {
                case 'a': return '[a@4*#+$]';
                case 'e': return '[e3*#+$]';
                case 'i': return '[i1l!|&y*#+$]';
                case 'o': return '[o0*#+$]';
                case 'u': return '[u*#+$]';
                case 'n': return '[nñ*#+$]';
                case 'y': return '[yjg*#+$]';
                case 'b': return '[b8*#+$]';
                case 'j': return '[jyg$*#+$]';
                case 'g': return '[g96*#+$]';
                case 'd': return '[d4*#+$]';
                case 's': return '[szc$52]';
                case 'c': return '[ckq*#+$]';
                default: return char;
            }
        }).join('');
        
        // Patrón para palabras completas
        const wholeWordPattern = new RegExp(`\\b${patternString}\\b`, 'i');
        
        // Patrón para palabras incrustadas
        const embeddedPattern = new RegExp(patternString, 'i');
        
        if (wholeWordPattern.test(normalizedText) || embeddedPattern.test(normalizedText)) {
            return true;
        }
    }
    return false;
}

export { loadCensorWords, containsCensoredWords };