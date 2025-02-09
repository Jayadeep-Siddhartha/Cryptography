
def create_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = "".join(dict.fromkeys(key.upper().replace("J", "I")))
    matrix = list(dict.fromkeys(key + alphabet))#Makes list in the order needed
    return [matrix[i:i+5] for i in range(0, 25, 5)] # makes matrix

def find_position(matrix, letter):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None, None

def playfair_encrypt(text, key):
    matrix = create_playfair_matrix(key)
    text = text.upper().replace("J", "I").replace(" ", "")
    # text_pairs = [text[i:i+2] if i+1 < len(text) else text[i]+'X' for i in range(0, len(text), 2)]

    encrypted_text = ""
    for i in range(0, len(text), 2):
        row1, col1 = find_position(matrix, text[i])
        row2, col2 = find_position(matrix, text[i+1])

        if row1 == row2:
            encrypted_text += matrix[row1][(col1+1) % 5] + matrix[row2][(col2+1) % 5]
        elif col1 == col2:
            encrypted_text += matrix[(row1+1) % 5][col1] + matrix[(row2+1) % 5][col2]
        else:
            encrypted_text += matrix[row1][col2] + matrix[row2][col1]

    return encrypted_text

def playfair_decrypt(text, key):
    matrix = create_playfair_matrix(key)
    decrypted_text = ""
    for i in range(0, len(text), 2):
        row1, col1 = find_position(matrix, text[i])
        row2, col2 = find_position(matrix, text[i+1])

        if row1 == row2:
            decrypted_text += matrix[row1][(col1-1) % 5] + matrix[row2][(col2-1) % 5]
        elif col1 == col2:
            decrypted_text += matrix[(row1-1) % 5][col1] + matrix[(row2-1) % 5][col2]
        else:
            decrypted_text += matrix[row1][col2] + matrix[row2][col1]

    return decrypted_text
