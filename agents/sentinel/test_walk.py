import os

# The "." tells Python to start in your current project folder
for current_folder, subfolders, files in os.walk("."):
    
    print(f"I am currently looking inside: {current_folder}")
    
    # Now let's look at the items on the desk
    for file in files:
        print(f"  -> Found a file: {file}")
        
    print("-----------------------------------")