import sqlite3
import re

def keyword_in_python_comment(content, keyword):
    """ Returns True if the keyword appears inside a Python comment. """
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            if keyword.lower() in stripped.lower():
                return True
    return False

def keyword_in_c_comment(content, keyword):
    """ Returns True if the keyword appears inside a C comment (// or /* */). """
    keyword_lower = keyword.lower()
    
    # Check // single-line comments
    for line in content.splitlines():
        stripped = line.strip()
        if '//' in stripped:
            comment_part = stripped[stripped.index('//')+2:]
            if keyword_lower in comment_part.lower():
                return True
                
    # Check /* multi-line */ comments
    multiline_pattern = r'/\*.*?\*/'
    for match in re.finditer(multiline_pattern, content, re.DOTALL):
        if keyword_lower in match.group().lower():
            return True
            
    return False

def verify_all_files():
    conn = sqlite3.connect('corpus.db')
    c = conn.cursor()
    
    # Column add karne ki koshish karo agar nahi hai toh
    try:
        c.execute('ALTER TABLE raw_files ADD COLUMN keyword_in_comment INTEGER DEFAULT NULL')
        conn.commit()
    except:
        pass  # Column pehle se hai toh koi baat nahi

    rows = c.execute('SELECT id, language, file_content, search_keyword FROM raw_files WHERE keyword_in_comment IS NULL').fetchall()
    print(f'Verifying {len(rows)} files...')
    
    confirmed = 0
    rejected = 0
    
    for row_id, language, content, keyword in rows:
        if content is None:
            result = 0
        elif language == 'Python':
            if keyword_in_python_comment(content, keyword):
                result = 1
            else:
                result = 0
        else:  # C Language
            if keyword_in_c_comment(content, keyword):
                result = 1
            else:
                result = 0
                
        c.execute('UPDATE raw_files SET keyword_in_comment = ? WHERE id = ?', (result, row_id))
        if result == 1:
            confirmed += 1
        else:
            rejected += 1
            
    conn.commit()
    conn.close()
    print(f'Verification complete. Keyword in comment: {confirmed} | Rejected: {rejected}')

if __name__ == '__main__':
    verify_all_files()