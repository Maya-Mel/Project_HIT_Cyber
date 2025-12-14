import configparser
import os

def validate_password_security (password):

    config = configparser.ConfigParser()
    config.read('password_config.ini')

    settings = config['PASSWORD']

    min_len = int(settings.get('MIN_LENGTH', 8))
    if len(password) < min_len:
        return f"must have at least {min_len} char"
    
    if settings.getboolean('REQUIRE_LOWER'):
        if not any(char.islower() for char in password):
            return "Must have at least one lower case and one upper case"
        
    if settings.getboolean('REQUIRE_DIGIT'):
        if not any(char.isdigit() for char in password):
            return "Must have a number"
        
    if settings.getboolean('REQUIRE_SPECIAL'):
        special_chars = {'@','!'}
        if not any(char in special_chars for char in password):
            return "Must contain special char"
        
    dict_file = settings.get('DICTIONARY_FILE')
    if dict_file and os.path.exists(dict_file):
        try:
            with open(dict_file, 'r', encoding='utf-8') as f:
                forbidden_passwords = {line.strip().lower() for line in f}
                
            if password.lower() in forbidden_passwords:
                return "Cant Contaon certin Words"
        except Exception as e:
            print(f"Warning: Could not read dictionary file: {e}")

    return None
