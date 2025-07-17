const ejs = require('ejs');
const fs = require('fs');
const path = require('path');

const renderEJS = (filePath) => {
    const template = fs.readFileSync(filePath, 'utf-8');
    const html = ejs.render(template);
    const outputFilePath = path.join(__dirname, 'public', path.basename(filePath, '.ejs') + '.html');
    fs.writeFileSync(outputFilePath, html);
};

const viewsDir = path.join(__dirname, 'views');
const files = fs.readdirSync(viewsDir);

if (!fs.existsSync('public')) {
    fs.mkdirSync('public');
}

files.forEach(file => {
    if (file.endsWith('.ejs')) {
        renderEJS(path.join(viewsDir, file));
    }
});

console.log('EJS files have been compiled to HTML.');
