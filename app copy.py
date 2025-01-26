# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory , jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
from functools import wraps
from datetime import datetime
from PIL import Image
#import pytesseract
import re
from difflib import SequenceMatcher
import logging
from urllib.parse import urlparse
import requests# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory , jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
from functools import wraps
from datetime import datetime
from PIL import Image
import pytesseract
import re
from difflib import SequenceMatcher
import logging
from urllib.parse import urlparse
import requests
import glob
# Configure Tesseract path - update based on your server setup
#pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# App Configuration
app = Flask(__name__)
app.secret_key = os.urandom(24)
#OCR_API_KEY = "K86407102988957"
# Constants and Configurations
UPLOAD_FOLDER = 'static/uploads'
STATIC_FOLDER = 'static'
DATA_FOLDER = 'data'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
YEARS = ["3rd Year", "4th Year"]
BRANCHES = ["AIML" ,"AI", "CSE",  "CST"]
SECTIONS = ["A", "B","C","D"]

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)


# After your app initialization
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# File paths
USERS_FILE = os.path.join(DATA_FOLDER, 'users.json')
PROBLEMS_FILE = os.path.join(DATA_FOLDER, 'problems.json')
SUBMISSIONS_FILE = os.path.join(DATA_FOLDER, 'submissions.json')
CODE_FOLDER = 'static/code'
PROBLEM_ASSIGNMENTS_FILE = os.path.join(DATA_FOLDER, 'problem_assignments.json')
PROBLEMS_MASTER_FILE = os.path.join(DATA_FOLDER, 'problems_master.json')



def load_json_file(file_path):
    """Load and return JSON data from file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {file_path}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error loading {file_path}: {e}")
        return {}









# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        users = load_json_file(USERS_FILE)

        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            flash('Login successful!')
            if users[username]['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('student_dashboard'))

        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        year = request.form['year'].strip()
        branch = request.form['branch'].strip()
        section = request.form['section'].strip()

        if not all([username, password, year, branch, section]):
            flash('All fields are required.')
            return redirect(url_for('signup'))

        users = load_json_file(USERS_FILE)

        if username in users:
            flash('Username already exists.')
            return redirect(url_for('signup'))

        # Create the new user
        users[username] = {
            'password': generate_password_hash(password),
            'role': 'student',
            'year': year,
            'branch': branch,
            'section': section
        }
        save_json_file(USERS_FILE, users)

        # Load existing problems to assign to the new student
        problems = load_json_file(PROBLEMS_FILE)

        # Create a new entry for the new student if it doesn't exist
        if username not in problems:
            problems[username] = []

        # Collect problems to assign
        problems_to_assign = []

        # Check existing problem assignments and collect relevant ones
        # Check existing problem assignments and collect relevant ones
        for existing_username, student_problems in problems.items():
            for problem in student_problems:
                criteria = problem.get('criteria', {})

        # Extract criteria values
                year_criteria = criteria.get('year')
                branch_criteria = criteria.get('branch')
                section_criteria = criteria.get('section')

        # Check if the criteria match the new student's attributes
                if ((year_criteria == year or year_criteria == "All Years") and
                    (branch_criteria == branch or branch_criteria == "All Branches") and
                    (section_criteria == section or section_criteria == "All Sections")):problems_to_assign.append(problem)

        # Assign the collected problems to the new student
        for problem in problems_to_assign:
            if problem not in problems[username]:  # Avoid duplicates
                problems[username].append(problem)

        # Save updated problems
        save_json_file(PROBLEMS_FILE, problems)

        flash('Account created successfully!')
        return redirect(url_for('login'))

    return render_template('signup.html', years=YEARS, branches=BRANCHES, sections=SECTIONS)
def get_unique_problems(problems):
    """Extract unique problems from the problems data."""
    unique_problems = set()
    for user_problems in problems.values():
        for problem in user_problems:
            # Use both title and link to identify unique problems
            problem_identifier = (problem['title'], problem['link'])
            unique_problems.add(problem_identifier)

    return unique_problems



def calculate_completion_rates(students, submissions, problems):
    completion_rates = []
    for username in students:
        user_problems = problems.get(username, [])
        if user_problems:
            completed = len([sub for sub in submissions.get(username, {}).values() if sub['verified']])
            rate = (completed / len(user_problems)) * 100 if len(user_problems) > 0 else 0
            completion_rates.append((username, rate))
    return completion_rates

def calculate_average_completion_rate(completion_rates):
    if not completion_rates:
        return 0
    return sum(rate for _, rate in completion_rates) / len(completion_rates)




@app.route('/admin/verify_problem/<problem_title>', methods=['POST'])
@login_required
@admin_required
def verify_problem(problem_title):
    """Verify the specified problem for the student."""
    try:
        submissions = load_json_file(SUBMISSIONS_FILE)
        # Loop through all students to find the submission for this problem
        for username, user_submissions in submissions.items():
            if problem_title in user_submissions:
                user_submissions[problem_title]['verified'] = True
                user_submissions[problem_title]['verification_details'] = {
                    'manual_verification': True,
                    'verified_by': session['username'],
                    'timestamp': datetime.now().isoformat()
                }

        # Save the updated submissions
        save_json_file(SUBMISSIONS_FILE, submissions)

        flash(f'Problem "{problem_title}" has been verified successfully for all students.', 'success')
        return redirect(url_for('view_student_details', username=username))  # Redirect to the student details page

    except Exception as e:
        logger.error(f"Error verifying problem: {str(e)}", exc_info=True)
        flash('An error occurred while verifying the problem.', 'error')
        return redirect(url_for('admin_dashboard'))


USERS_FILE = 'data/users.json'  # Update this path as needed

@app.route('/get_code', methods=['GET'])
@login_required
def get_code():
    username = session['username']
    problem_title = request.args.get('problem_title')
    base_filename = f"{username}_{problem_title.replace(' ', '_')}"
    code_file_path = os.path.join(CODE_FOLDER, f"{base_filename}*.txt")
    code_files = glob.glob(code_file_path)

    if code_files:
        with open(code_files[0], 'r') as code_file:
            code_content = code_file.read()
        return jsonify({'code': code_content}), 200
    else:
        return jsonify({'code': ''}), 404

@app.route('/submit_code', methods=['POST'])
@login_required
def submit_code():
    try:
        # Get the submitted code and problem title from the form
        code = request.form.get('code')
        problem_title = request.form.get('problem_title')

        if not code:
            return jsonify({'verified': False, 'message': 'No code submitted.'}), 400

        # Generate a base filename based on the student's username and problem title
        username = session['username']
        base_filename = f"{username}_{problem_title.replace(' ', '_')}"
        file_path = os.path.join(CODE_FOLDER, f"{base_filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

        # Check if a previous submission exists for this problem
        old_file_path_pattern = os.path.join(CODE_FOLDER, f"{base_filename}*.txt")
        old_files = glob.glob(old_file_path_pattern)  # Use glob to find matching files

        # If an old file exists, delete it
        if old_files:
            for old_file in old_files:
                os.remove(old_file)

        # Save the new code to the file
        with open(file_path, 'w') as code_file:
            code_file.write(code)

        return jsonify({'verified': True, 'message': 'Code submitted successfully!'}), 200

    except Exception as e:
        logger.error(f"Error submitting code: {str(e)}", exc_info=True)
        return jsonify({'verified': False, 'message': 'Error processing submission.'}), 500


    return render_template(
        'student_dashboard.html',
        student=student_data,
        problems=student_problems,
        submissions=formatted_submissions
    )

USERS_FILE = 'data/users.json'  # Update this path as needed

def load_users():
    """Load users from the JSON file."""
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as file:
        return json.load(file)

def save_users(users):
    """Save users to the JSON file."""
    with open(USERS_FILE, 'w') as file:
        json.dump(users, file, indent=4)

def add_user(user_id, password, role, additional_info=None):
    """Add a new user to the users file."""
    users = load_users()
    if user_id not in users:
        users[user_id] = {
            "password": password,  # You should hash the password before saving
            "role": role
        }
        if additional_info:
            users[user_id].update(additional_info)
        save_users(users)

def delete_user(user_id):
    """Delete a user from the users file."""
    users = load_users()
    if user_id in users:
        del users[user_id]
        save_users(users)

@app.route('/admin/tools', methods=['GET', 'POST'])
@login_required
def admin_tools():
    pin_verified = session.get('pin_verified', False)

    if request.method == 'POST':
        # Handle PIN verification
        if not pin_verified:
            entered_pin = request.form.get('pin')
            if entered_pin == load_secret_pin():  # Check against the loaded PIN
                session['pin_verified'] = True
                flash('PIN verified successfully!', 'success')
                return redirect(url_for('admin_tools'))
            else:
                flash('Incorrect PIN. Please try again.', 'danger')
                return redirect(request.url)  # Redirect to avoid resubmission

        # Handle changing the PIN
        new_pin = request.form.get('new_pin')
        if new_pin:
            change_secret_pin(new_pin)  # Change the PIN
            flash('Secret PIN updated successfully!', 'success')

        # Handle adding a new student
        new_student_id = request.form.get('new_student_id')
        new_student_password = request.form.get('new_student_password')
        if new_student_id and new_student_password:
            add_user(new_student_id, new_student_password, "student", {
                "year": request.form.get('year'),
                "branch": request.form.get('branch'),
                "section": request.form.get('section')
            })
            flash(f'Student {new_student_id} added successfully!', 'success')

        # Handle deleting a user
        user_to_delete = request.form.get('user_to_delete')
        if user_to_delete:
            delete_user(user_to_delete)  # Delete the user
            flash(f'User  {user_to_delete} deleted successfully!', 'success')

        # Handle adding a new admin
        new_admin_id = request.form.get('new_admin_id')
        new_admin_password = request.form.get('new_admin_password')
        if new_admin_id and new_admin_password:
            add_user(new_admin_id, new_admin_password, "admin")  # Add the new admin
            flash(f'Admin {new_admin_id} added successfully!', 'success')

        # Handle adding users from file
        if 'file' in request.files:
            branch = request.form.get('branch')
            year = request.form.get('year')
            section = request.form.get('section')
            default_password = request.form.get('default_password')
            file = request.files['file']

            # Read the uploaded file
            if file.filename.endswith('.txt'):
                content = file.read().decode('utf-8')
                roll_numbers = [num.strip() for num in content.replace('\n', ',').split(',')]
            elif file.filename.endswith('.json'):
                roll_numbers = json.load(file)
            else:
                flash('Unsupported file format. Please upload a .txt or .json file.', 'danger')
                return redirect(request.url)

            # Load existing users
            users = load_users()

            # Load existing problems to assign to the new students
            problems = load_json_file(PROBLEMS_FILE)

            # Add each roll number as a new user and assign problems
            for roll_number in roll_numbers:
                roll_number = roll_number.strip()  # Clean up whitespace
                if roll_number and roll_number not in users:
                    hashed_password = generate_password_hash(default_password)
                    users[roll_number] = {
                        "password": hashed_password,
                        "role": "student",
                        "year": year,
                        "branch": branch,
                        "section": section
                    }

                    # Create a new entry for the new student if it doesn't exist
                    if roll_number not in problems:
                        problems[roll_number] = []

                    # Collect problems to assign
                    problems_to_assign = []

                    # Check existing problem assignments and collect relevant ones
                    for existing_username, student_problems in problems.items():
                        for problem in student_problems:
                            criteria = problem.get('criteria', {})
                            year_criteria = criteria.get('year')
                            branch_criteria = criteria.get('branch')
                            section_criteria = criteria.get('section')

                            # Check if the criteria match the new student's attributes
                            if ((year_criteria == year or year_criteria == "All Years") and
                                ( branch_criteria == branch or branch_criteria == "All Branches") and
                                (section_criteria == section or section_criteria == "All Sections")):
                                problems_to_assign.append(problem)

                    # Assign the collected problems to the new student
                    for problem in problems_to_assign:
                        if problem not in problems[roll_number]:  # Avoid duplicates
                            problems[roll_number].append(problem)

            # Save updated users and problems to the JSON files
            save_users(users)
            save_json_file(PROBLEMS_FILE, problems)
            flash('Users added and problems assigned successfully!', 'success')

        # Handle file uploads
        if 'upload_file' in request.files:
            upload_file = request.files['upload_file']
            if upload_file and upload_file.filename:
                # Save the file in the specified static folder
                folder_path = request.form.get('folder_path', STATIC_FOLDER)
                upload_path = os.path.join(folder_path, secure_filename(upload_file.filename))
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)  # Create folder if it doesn't exist
                upload_file.save(upload_path)
                flash('File uploaded successfully!', 'success')

    # Load the current directory or subdirectory
    current_path = request.args.get('path', STATIC_FOLDER)
    if not os.path.exists(current_path):
        flash('Directory does not exist.', 'danger')
        return redirect(url_for('admin_tools'))

    # List directories and files
    directories = []
    files = []
    for item in os.listdir(current_path):
        item_path = os.path.join(current_path, item)
        if os.path.isdir(item_path):
            directories.append(item)  # Just store the name
        else:
            files.append(item)  # Just store the name

    # Load the list of users
    users = load_users()  # Load the list of users
    return render_template(
        'admin_tools.html',
        pin_verified=pin_verified,
        users=users,
        years=YEARS,
        branches=BRANCHES,
        sections=SECTIONS,
        directories=directories,
        files=files,
        current_path=current_path
    )
@app.route('/admin/tools/download')
@login_required
def download_file():
    # Get the full path from the query parameters
    file_path = request.args.get('file_path')
    if not file_path or not os.path.exists(file_path):
        flash('File not found.', 'danger')
        return redirect(url_for('admin_tools'))

    return send_from_directory(os.path.dirname(file_path), os.path.basename(file_path), as_attachment=True)

@app.route('/admin/tools/delete', methods=['POST'])
@login_required
def delete_files():
    current_path = request.form.get('current_path')
    files_to_delete = request.form.getlist('files_to_delete')

    for file in files_to_delete:
        file_path = os.path.join(current_path, file)
        if os.path.isfile(file_path):
            os.remove(file_path)  # Delete the file
            flash(f'File {file} deleted successfully!', 'success')
        else:
            flash(f'File {file} not found or is not a file.', 'danger')

    return redirect(url_for('admin_tools', path=current_path))
# Additional functions for loading and changing the secret PIN
def load_secret_pin():
    # Load the secret PIN from a secure location (e.g., environment variable or config file)
    return "Garuda"  # Example PIN, replace with actual loading logic

def change_secret_pin(new_pin):
    # Save the new PIN to a secure location (e.g., environment variable or config file)
    pass  # Replace with actual saving logic





def normalize_url(url):
    """Normalize URL for comparison"""
    if not url:
        return ""
    url = url.lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url.strip()

def extract_problem_link(text):
    """Extract GeeksForGeeks problem link from text"""
    if not text:
        logger.debug("Empty text provided to extract_problem_link")
        return None

    patterns = [
        r'geeksforgeeks\.org\/problems\/[a-zA-Z0-9-]+\/\d+',
        r'problems\/[a-zA-Z0-9-]+\/\d+',
        r'geeksforgeeks\.org\/[a-zA-Z0-9-]+\/\d+',

        r'practice\.geeksforgeeks\.org\/problems?\/[a-zA-Z0-9-]+(?:\/\d+)?',
        r'leetcode\.com/problems/[a-zA-Z0-9-]+/submissions/?',
        r'hackerrank\.com/challenges/[a-zA-Z0-9-]+/problem/?',
        r'www\.hackerearth\.com/problem/.*/',
        r'www\.hackerearth\.com/problems/.*/',
        r'www\.naukri\.com/code360/problems/[a-zA-Z0-9-]+_\d+'
    ]

    logger.debug(f"Searching for URL patterns in text: {text[:100]}...")  # Log first 100 chars

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            logger.debug(f"Found URL match: {match.group(0)}")
            return match.group(0)

    logger.debug("No URL pattern matched in the text")
    return None

def check_problem_solved(text):
    """Check if problem is marked as solved in the text"""
    if not text:
        logger.debug("Empty text provided to check_problem_solved")
        return False

    solved_patterns = [
        r'problem solved successfully',
        r'solved successfully',
        r'correct answer',
        r'success',
        r'Correct',
        r'all test cases passed',
        r'submission details.*?successful',
        r'accepted',
        r'test cases:\s*\d+\s*\/\s*\d+',  # Matches "Test Cases: X/Y" pattern
        r'runtime:\s*[\d.]+\s*(?:ms|s)',  # Matches runtime information
    ]

    logger.debug(f"Checking solved patterns in text: {text[:100]}...")

    for pattern in solved_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            logger.debug(f"Found solved pattern match: {match.group(0)}")
            return True

    logger.debug("No solved patterns matched in the text")
    return False



def verify_submission_with_ocr(ocr_text, expected_link, image_path):
    """
    Enhanced verification using modular URL and solved status checking
    """
    try:
        print(f"Verifying Submission:")
        print(f"Expected Link: {expected_link}")
        print(f"OCR Text: {ocr_text}")

        # Normalize expected link
        normalized_expected_link = normalize_url(expected_link)
        print(f"Normalized Expected Link: {normalized_expected_link}")

        # Extract problem link from OCR text
        extracted_link = extract_problem_link(ocr_text)
        print(f"Extracted Link: {extracted_link}")

        # Normalize extracted link
        normalized_extracted_link = normalize_url(extracted_link) if extracted_link else None
        print(f"Normalized Extracted Link: {normalized_extracted_link}")

        # Link matching
        link_matched = (
            normalized_extracted_link and
            (normalized_extracted_link in normalized_expected_link or
             normalized_expected_link in normalized_extracted_link)
        )
        print(f"Link Matched: {link_matched}")

        # Check if problem is solved
        problem_solved = check_problem_solved(ocr_text)
        print(f"Problem Solved: {problem_solved}")

        # Verification result
        verification_result = {
            'verified': link_matched and problem_solved,
            'link_matched': link_matched,
            'problem_solved': problem_solved,
            'extracted_link': extracted_link,
            'extracted_text': ocr_text
        }

        print("Verification Result:")
        print(verification_result)

        return verification_result

    except Exception as e:
        print(f"Verification Error: {str(e)}")
        return {
            'verified': False,
            'error': str(e)
        }

def debug_verification_process(image_path, expected_link, ocr_api_key):
    """
    Debug helper function that tests each step of the verification process
    and returns detailed diagnostic information
    """
    debug_info = {
        "ocr_response": None,
        "extracted_text": None,
        "link_extraction": None,
        "url_matching": None,
        "solved_check": None,
        "final_status": None,
        "error": None
    }

    try:
        # 1. Test OCR API call
        with open(image_path, 'rb') as image_file:
            payload = {
                'apikey': ocr_api_key,
                'OCREngine': '2',
                'scale': 'true',
                'isTable': 'true',
                'detectOrientation': 'true'
            }
            files = {'file': image_file}

            response = requests.post(
                'https://api.ocr.space/parse/image',
                files=files,
                data=payload
            )
            debug_info["ocr_response"] = {
                "status_code": response.status_code,
                "response_headers": dict(response.headers)
            }

            if not response.ok:
                debug_info["error"] = f"OCR API error: {response.status_code}"
                return debug_info

            result = response.json()
            extracted_text = result.get('ParsedResults', [{}])[0].get('ParsedText', '')
            debug_info["extracted_text"] = extracted_text

            # 2. Test link extraction
            extracted_link = extract_problem_link(extracted_text)
            debug_info["link_extraction"] = {
                "extracted_link": extracted_link,
                "expected_link": expected_link
            }

            # 3. Test URL matching
            if extracted_link:
                normalized_expected = normalize_url(expected_link)
                normalized_extracted = normalize_url(extracted_link)
                debug_info["url_matching"] = {
                    "normalized_expected": normalized_expected,
                    "normalized_extracted": normalized_extracted,
                    "matches": (normalized_extracted in normalized_expected or
                              normalized_expected in normalized_extracted)
                }

            # 4. Test solved status check
            debug_info["solved_check"] = {
                "is_solved": check_problem_solved(extracted_text),
                "text_snippets": re.findall(r'((?:submitted|successful|solved|passed).*?(?:\.|$))',
                                          extracted_text,
                                          re.IGNORECASE)
            }

            # 5. Final verification status
            debug_info["final_status"] = {
                "verified": (debug_info["url_matching"]["matches"] if debug_info["url_matching"] else False) and
                           debug_info["solved_check"]["is_solved"]
            }

    except Exception as e:
        debug_info["error"] = str(e)

    return debug_info
# Replace the existing verify_submission_image function with this one
#verify_submission_image = verify_solution_with_ocr
def debug_verification(image_path, expected_link):
    """
    Debug helper function to print detailed verification process
    """
    print(f"\nTesting verification for image: {image_path}")
    print(f"Expected link: {expected_link}")
    print("\n" + "="*50)

    try:
        text = pytesseract.image_to_string(Image.open(image_path))
        print("\nExtracted Text:")
        print("-"*50)
        print(text)

        is_verified, details = verify_submission_image(image_path, expected_link)

        print("\nVerification Results:")
        print("-"*50)
        print(f"Verification passed: {is_verified}")
        print("Details:")
        for key, value in details.items():
            print(f"  {key}: {value}")

        return is_verified, details

    except Exception as e:
        print(f"Debug error: {str(e)}")
        return False, {'error': str(e)}
# Update the Submission model in the JSON structure
def update_submission_verification(username, problem_title, filename, verification_status, verification_details):
    """Update the submission with verification status"""
    submissions = load_json_file(SUBMISSIONS_FILE)

    if username not in submissions:
        submissions[username] = {}

    submissions[username][problem_title] = {
        'filename': filename,
        'verified': verification_status,
        'verification_details': verification_details,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    save_json_file(SUBMISSIONS_FILE, submissions)


# Update the submit_solution route error handling
def handle_verification_error(error_details):
    """Handle verification error details"""
    error_msg = error_details.get('error', 'Unknown error')
    return f"Verification failed: {error_msg}"

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Initialize data files on startup
init_data_files()




@app.route('/admin/tools/clear_students', methods=['POST'])
@login_required
@admin_required
def clear_students():
    users = load_json_file(USERS_FILE)
    problems = load_json_file(PROBLEMS_FILE)
    submissions = load_json_file(SUBMISSIONS_FILE)

    # Keep only admin users
    users = {username: data for username, data in users.items() if data.get('role') == 'admin'}

    # Clear problems and submissions
    problems.clear()
    submissions.clear()

    # Save cleared data
    save_json_file(USERS_FILE, users)
    save_json_file(PROBLEMS_FILE, problems)
    save_json_file(SUBMISSIONS_FILE, submissions)

    flash('All student data has been cleared.')
    return redirect(url_for('admin_dashboard'))


'''@app.route('/resubmit_solution', methods=['POST'])
def resubmit_solution():
    if 'screenshot' not in request.files:
        flash("No file uploaded", "error")
        return redirect(url_for('dashboard'))

    file = request.files['screenshot']
    problem_title = request.form.get('problem_title')

    if file.filename == '':
        flash("No file selected", "error")
        return redirect(url_for('dashboard'))

    # Save the file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Update submission record (e.g., mark as 'Pending' again)
    update_submission(problem_title, filename, verified=False)

    flash("Solution resubmitted successfully!", "success")
    return redirect(url_for('dashboard'))


'''
if __name__ == '__main__':
    app.run(debug=True, threaded=True)

# Configure Tesseract path - update based on your server setup
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# App Configuration
app = Flask(__name__)
app.secret_key = os.urandom(24)
OCR_API_KEY = "K86407102988957"
# Constants and Configurations
UPLOAD_FOLDER = 'static/uploads'
DATA_FOLDER = 'data'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
YEARS = ["3rd Year", "4th Year"]
BRANCHES = ["AIML" ,"AI", "CSE",  "CST"]
SECTIONS = ["A", "B","C","D"]

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)


# After your app initialization
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# File paths
USERS_FILE = os.path.join(DATA_FOLDER, 'users.json')
PROBLEMS_FILE = os.path.join(DATA_FOLDER, 'problems.json')
SUBMISSIONS_FILE = os.path.join(DATA_FOLDER, 'submissions.json')
PROBLEM_ASSIGNMENTS_FILE = os.path.join(DATA_FOLDER, 'problem_assignments.json')
PROBLEMS_MASTER_FILE = os.path.join(DATA_FOLDER, 'problems_master.json')
# Helper Functions
def init_data_files():
    """Initialize JSON data files if they don't exist."""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({
                "admin": {
                    "password": generate_password_hash("admin123"),
                    "role": "admin"
                }
            }, f)
    
    if not os.path.exists(PROBLEMS_FILE):
        with open(PROBLEMS_FILE, 'w') as f:
            json.dump({}, f)
            
    if not os.path.exists(SUBMISSIONS_FILE):
        with open(SUBMISSIONS_FILE, 'w') as f:
            json.dump({}, f)

def allowed_file(filename):
    """Check if uploaded file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_json_file(file_path):
    """Load and return JSON data from file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading {file_path}: {e}")
        return {}

def save_json_file(file_path, data):
    """Save data to JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving {file_path}: {e}")

def get_user_role(username):
    """Get user role from users data."""
    users = load_json_file(USERS_FILE)
    return users.get(username, {}).get('role')

def calculate_similarity(str1, str2):
    """Calculate string similarity ratio"""
    return SequenceMatcher(None, str1, str2).ratio()

def clean_link(url):
    """Clean and normalize link for comparison"""
    url = url.lower()
    url = url.replace('os', '0s')
    url = re.sub(r'[^\w./\-]', '', url)
    for prefix in ['https://', 'http://', 'www.']:
        url = url.replace(prefix, '')
    return url.strip('/')

def debug_ocr(image_path):
    """Perform OCR and print debug output"""
    try:
        text = pytesseract.image_to_string(Image.open(image_path))
        
        print("\n" + "="*50)
        print("RAW OCR TEXT OUTPUT")
        print("="*50)
        
        lines = text.split('\n')
        print("\nText by lines:")
        print("-"*50)
        for i, line in enumerate(lines, 1):
            print(f"Line {i:02d}: {repr(line)}")
        
        print("\nContinuous text:")
        print("-"*50)
        print(repr(text))
        
        print("\nText statistics:")
        print("-"*50)
        print(f"Total lines: {len(lines)}")
        print(f"Total characters: {len(text)}")
        print(f"Non-empty lines: {sum(1 for line in lines if line.strip())}")
        print("="*50 + "\n")
        
        return text
    except Exception as e:
        print(f"OCR Error: {str(e)}")
        return None

def debug_link_extraction(text, expected_link):
    """Debug link extraction and matching"""
    link_pattern = r'(?:https?://)?(?:www\.)?[^\s]+?geeksforgeeks\.org[^\s]+'
    link_matches = re.finditer(link_pattern, text)
    
    best_match = None
    best_similarity = 0
    
    cleaned_expected = clean_link(expected_link)
    print(f"Cleaned expected link: {cleaned_expected}")
    
    for match in link_matches:
        extracted_link = match.group(0)
        cleaned_extracted = clean_link(extracted_link)
        similarity = calculate_similarity(cleaned_extracted, cleaned_expected)
        
        print(f"\nFound link: {extracted_link}")
        print(f"Cleaned extracted: {cleaned_extracted}")
        print(f"Similarity score: {similarity:.2f}")
        
        if similarity > best_similarity:
            best_similarity = similarity
            best_match = cleaned_extracted

    print(f"\nBest match found: {best_match}")
    print(f"Best similarity score: {best_similarity:.2f}")
    
    is_match = best_similarity >= 0.6
    print(f"Link match result: {is_match}")
    print("="*50 + "\n")
    return is_match, best_match, best_similarity

def debug_test_cases(text):
    """Debug test case extraction"""
    print("=== TEST CASES DEBUGGING ===")
    
    patterns = [
        (r'Test Cases Passed[^\d]*(\d+)\s*/\s*(\d+)', 'Test Cases Passed format'),
        (r'Test Cases.*?(\d+)\s*/\s*(\d+)', 'Test Cases nearby format'),
        (r'(\d+)\s*/\s*(\d+)(?:\s*test cases|\s*Test Cases)', 'Test cases suffix format'),
        (r'Passed:\s*(\d+)/(\d+)', 'Passed format'),
    ]
    
    found_matches = []
    for pattern, desc in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
        for match in matches:
            passed, total = match.groups()
            print(f"\nPattern ({desc}):")
            print(f"Found match: {match.group(0)}")
            print(f"Passed: {passed}")
            print(f"Total: {total}")
            
            try:
                p, t = int(passed), int(total)
                if p <= t:
                    found_matches.append((p, t, desc))
            except ValueError:
                print(f"Invalid numbers in match: {passed}/{total}")
    
    if not found_matches:
        print("No test case matches found!")
        return None, None
    
    priority_order = {
        'Test Cases Passed format': 0,
        'Test Cases nearby format': 1,
        'Test cases suffix format': 2,
        'Passed format': 3
    }
    
    found_matches.sort(key=lambda x: (priority_order.get(x[2], 999), -x[1]))
    passed, total, desc = found_matches[0]
    
    print(f"\nSelected match: {passed}/{total} (using {desc})")
    print("="*50 + "\n")
    
    return passed, total, desc

def test_verification(image_path, expected_link):
    """Test complete verification process"""
    print(f"\nTesting verification for image: {image_path}")
    print(f"Expected link: {expected_link}")
    print("\n" + "="*50 + "\n")
    
    text = debug_ocr(image_path)
    if not text:
        return False, {"error": "OCR failed"}
    
    link_matches, best_match, similarity = debug_link_extraction(text, expected_link)
    passed, total, desc = debug_test_cases(text)
    
    if passed is None or total is None:
        return False, {
            "error": "Could not extract test cases",
            "link_matched": link_matches,
            "extracted_link": best_match,
            "similarity_score": similarity
        }
    
    print("=== FINAL VERIFICATION ===")
    all_tests_passed = passed == total
    is_verified = link_matches and all_tests_passed
    
    verification_details = {
        'link_matched': link_matches,
        'extracted_link': best_match,
        'expected_link': clean_link(expected_link),
        'test_cases': f"{passed}/{total}",
        'all_tests_passed': all_tests_passed,
        'similarity_score': similarity,
        'test_case_format': desc
    }
    
    print(f"Link matches: {link_matches}")
    print(f"All tests passed ({passed}/{total}): {all_tests_passed}")
    print(f"Final verification result: {is_verified}")
    print("="*50)
    
    return is_verified, verification_details
def get_filtered_students(year=None, branch=None, section=None):
    """Get filtered list of students based on criteria."""
    users = load_json_file(USERS_FILE)
    filtered_students = {}
    
    for username, user_data in users.items():
        if user_data.get('role') == 'student':
            should_include = True
            
            if year and year != 'All Years':
                should_include = should_include and user_data.get('year') == year
            if branch and branch != 'All Branches':
                should_include = should_include and user_data.get('branch') == branch
            if section and section != 'All Sections':
                should_include = should_include and user_data.get('section') == section
            
            if should_include:
                filtered_students[username] = user_data
            else:
                logger.debug(f"Excluded student: {username}, Reason: {year}, {branch}, {section}")

    return filtered_students

def calculate_performance_metrics():
    """Calculate overall performance metrics."""
    users = load_json_file(USERS_FILE)
    problems = load_json_file(PROBLEMS_FILE)
    submissions = load_json_file(SUBMISSIONS_FILE)

    # Count total students
    total_students = len([u for u in users.values() if u.get('role') == 'student'])
    
    # Track unique problems using a set of (title, link) tuples
    unique_problems = set()
    for user_problems in problems.values():
        for problem in user_problems:
            # Use both title and link to identify unique problems
            problem_identifier = (problem['title'], problem['link'])
            unique_problems.add(problem_identifier)
    
    # Count unique problems
    active_problems = len(unique_problems)
    
    # Calculate completion rates
    completion_rates = []
    for username, user_probs in problems.items():
        if user_probs:
            completed = len(submissions.get(username, {}))
            rate = (completed / len(user_probs)) * 100 if len(user_probs) > 0 else 0
            completion_rates.append(rate)
    
    avg_completion_rate = round(sum(completion_rates) / len(completion_rates), 1) if completion_rates else 0

    return {
        'total_students': total_students,
        'active_problems': active_problems,
        'avg_completion_rate': avg_completion_rate
    }

# Decorators

# Route decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or get_user_role(session['username']) != 'admin':
            flash('Admin access required.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_json_file(USERS_FILE)

        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            flash('Login successful!')
            if users[username]['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('student_dashboard'))
        
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        year = request.form['year'].strip()
        branch = request.form['branch'].strip()
        section = request.form['section'].strip()

        if not all([username, password, year, branch, section]):
            flash('All fields are required.')
            return redirect(url_for('signup'))

        users = load_json_file(USERS_FILE)
        
        if username in users:
            flash('Username already exists.')
            return redirect(url_for('signup'))

        # Create the new user
        users[username] = {
            'password': generate_password_hash(password),
            'role': 'student',
            'year': year,
            'branch': branch,
            'section': section
        }
        save_json_file(USERS_FILE, users)

        # Load existing problems to assign to the new student
        problems = load_json_file(PROBLEMS_FILE)

        # Create a new entry for the new student if it doesn't exist
        if username not in problems:
            problems[username] = []

        # Collect problems to assign
        problems_to_assign = []

        # Check existing problem assignments and collect relevant ones
        # Check existing problem assignments and collect relevant ones
        for existing_username, student_problems in problems.items():
            for problem in student_problems:
                criteria = problem.get('criteria', {})
        
        # Extract criteria values
                year_criteria = criteria.get('year')
                branch_criteria = criteria.get('branch')
                section_criteria = criteria.get('section')

        # Check if the criteria match the new student's attributes
                if ((year_criteria == year or year_criteria == "All Years") and
                    (branch_criteria == branch or branch_criteria == "All Branches") and
                    (section_criteria == section or section_criteria == "All Sections")):problems_to_assign.append(problem)

        # Assign the collected problems to the new student
        for problem in problems_to_assign:
            if problem not in problems[username]:  # Avoid duplicates
                problems[username].append(problem)

        # Save updated problems
        save_json_file(PROBLEMS_FILE, problems)

        flash('Account created successfully!')
        return redirect(url_for('login'))

    return render_template('signup.html', years=YEARS, branches=BRANCHES, sections=SECTIONS)
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    year = request.args.get('year', 'All Years')
    branch = request.args.get('branch', 'All Branches')
    section = request.args.get('section', 'All Sections')
    
    # If the year, branch, or section is set to "All", pass None to the filter
    filtered_year = year if year != 'All Years' else None
    filtered_branch = branch if branch != 'All Branches' else None
    filtered_section = section if section != 'All Sections' else None

    students = get_filtered_students(filtered_year, filtered_branch, filtered_section)
    problems = load_json_file(PROBLEMS_FILE)
    submissions = load_json_file(SUBMISSIONS_FILE)
    metrics = calculate_performance_metrics()

    return render_template(
        'admin_dashboard.html',
        students=students,
        problems=problems,
        submissions=submissions,
        years=YEARS,
        branches=BRANCHES,
        sections=SECTIONS,
        current_year=year,
        current_branch=branch,
        current_section=section,
        **metrics
    )
@app.route('/admin/bulk-assign', methods=['POST'])
@login_required
@admin_required
def bulk_assign():
    year = request.form['year']
    branch = request.form['branch']
    section = request.form['section']
    problem_title = request.form['problem_title']
    problem_link = request.form['problem_link']
    
    # Input validation
    if not all([problem_title, problem_link]):
        flash('Problem title and link are required.')
        return redirect(url_for('admin_dashboard'))
    
    # Get filtered students based on criteria
    students = get_filtered_students(year, branch, section)
    
    # Load existing problems
    problems = load_json_file(PROBLEMS_FILE)
    
    # Create new problem entry
    new_problem = {
        'title': problem_title,
        'link': problem_link,
        'assigned_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'criteria': {
            'year': year,
            'branch': branch,
            'section': section
        }
    }
    
    # Assign problem to each filtered student
    assign_count = 0
    for username in students:
        if username not in problems:
            problems[username] = []
            
        # Check if problem already assigned
        if not any(p['title'] == problem_title for p in problems[username]):
            problems[username].append(new_problem)
            assign_count += 1
    
    # Save updated problems
    save_json_file(PROBLEMS_FILE, problems)
    
    flash(f'Problem "{problem_title}" assigned to {assign_count} students.')
    return redirect(url_for('admin_dashboard'))
    
    # Assign problem to each filtered student
    assign_count = 0
    for username in students:
        if username not in problems:
            problems[username] = []
            
        # Check if problem already assigned
        if not any(p['title'] == problem_title for p in problems[username]):
            problems[username].append(new_problem)
            assign_count += 1
    
    # Save updated problems
    save_json_file(PROBLEMS_FILE, problems)
    
    flash(f'Problem "{problem_title}" assigned to {assign_count} students.')
    return redirect(url_for('admin_dashboard'))




# Student routes
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    username = session['username']
    users = load_json_file(USERS_FILE)
    problems = load_json_file(PROBLEMS_FILE)
    submissions = load_json_file(SUBMISSIONS_FILE)
    
    student_data = users.get(username, {})
    student_problems = problems.get(username, [])
    student_submissions = submissions.get(username, {})
    
    # Convert submissions data to the expected format
    formatted_submissions = {}
    for problem_title, submission_data in student_submissions.items():
        if isinstance(submission_data, dict):  # Handle new format
            formatted_submissions[problem_title] = submission_data
        else:  # Handle old format (if any)
            formatted_submissions[problem_title] = {
                'filename': submission_data,
                'verified': False,
                'verification_details': {},
                'timestamp': None
            }
    
    return render_template(
        'student_dashboard.html',
        student=student_data,
        problems=student_problems,
        submissions=formatted_submissions
    )



def normalize_url(url):
    """Normalize URL for comparison"""
    if not url:
        return ""
    url = url.lower()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url.strip()


def check_problem_solved(text):
    """Check if problem is marked as solved in the text"""
    if not text:
        logger.debug("Empty text provided to check_problem_solved")
        return False
        
    solved_patterns = [
        r'problem solved successfully',
        r'solved successfully',
        r'correct answer',
        r'success',
        r'all test cases passed',
        r'submission details.*?successful',
        r'accepted',  # Common success indicator
        r'test cases:\s*\d+\s*\/\s*\d+',  # Matches "Test Cases: X/Y" pattern
        r'runtime:\s*[\d.]+\s*(?:ms|s)',  # Matches runtime information
    ]
    
    logger.debug(f"Checking solved patterns in text: {text[:100]}...")
    
    for pattern in solved_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            logger.debug(f"Found solved pattern match: {match.group(0)}")
            return True
    
    logger.debug("No solved patterns matched in the text")
    return False

@app.route('/submit_solution', methods=['POST'])
@login_required
def submit_solution():
    try:
        # Log all incoming form data for debugging
        print("Received Form Data:")
        for key, value in request.form.items():
            print(f"{key}: {value}")
        
        username = session['username']
        problem_title = request.form.get('problem_title')
        ocr_text = request.form.get('ocr_text', '')

        print(f"OCR Text Received: {ocr_text}")

        # Existing file handling
        if 'screenshot' not in request.files:
            return jsonify({'verified': False, 'message': 'No file uploaded'}), 400

        file = request.files['screenshot']
        if file.filename == '':
            return jsonify({'verified': False, 'message': 'No selected file'}), 400

        # Get problem details
        problems = load_json_file(PROBLEMS_FILE)
        student_problems = problems.get(username, [])
        problem = next((p for p in student_problems if p['title'] == problem_title), None)

        if not problem:
            return jsonify({'verified': False, 'message': 'Problem not found'}), 404

        # Save the file
        filename = secure_filename(f"{username}_{problem_title}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Verification logic using OCR text
        verification_result = verify_submission_with_ocr(
            ocr_text, 
            problem['link'], 
            filepath
        )

        # Update submissions
        submissions = load_json_file(SUBMISSIONS_FILE)
        if username not in submissions:
            submissions[username] = {}

        submissions[username][problem_title] = {
            'filename': filename,
            'verified': verification_result['verified'],
            'verification_details': verification_result,
            'timestamp': datetime.now().isoformat()
        }

        save_json_file(SUBMISSIONS_FILE, submissions)

        # Return verification result
        return jsonify(verification_result)

    except Exception as e:
        print(f"Submission Error: {str(e)}")
        return jsonify({
            'verified': False, 
            'message': f"Error processing submission: {str(e)}"
        }), 500
def verify_submission_with_ocr(ocr_text, expected_link, image_path):
    """
    Enhanced verification using modular URL and solved status checking
    """
    try:
        print(f"Verifying Submission:")
        print(f"Expected Link: {expected_link}")
        print(f"OCR Text: {ocr_text}")

        # Normalize expected link
        normalized_expected_link = normalize_url(expected_link)
        print(f"Normalized Expected Link: {normalized_expected_link}")

        # Extract problem link from OCR text
        extracted_link = extract_problem_link(ocr_text)
        print(f"Extracted Link: {extracted_link}")

        # Normalize extracted link
        normalized_extracted_link = normalize_url(extracted_link) if extracted_link else None
        print(f"Normalized Extracted Link: {normalized_extracted_link}")

        # Link matching
        link_matched = (
            normalized_extracted_link and 
            (normalized_extracted_link in normalized_expected_link or 
             normalized_expected_link in normalized_extracted_link)
        )
        print(f"Link Matched: {link_matched}")

        # Check if problem is solved
        problem_solved = check_problem_solved(ocr_text)
        print(f"Problem Solved: {problem_solved}")

        # Verification result
        verification_result = {
            'verified': link_matched and problem_solved,
            'link_matched': link_matched,
            'problem_solved': problem_solved,
            'extracted_link': extracted_link,
            'extracted_text': ocr_text
        }

        print("Verification Result:")
        print(verification_result)

        return verification_result

    except Exception as e:
        print(f"Verification Error: {str(e)}")
        return {
            'verified': False,
            'error': str(e)
        }

def debug_verification_process(image_path, expected_link, ocr_api_key):
    """
    Debug helper function that tests each step of the verification process
    and returns detailed diagnostic information
    """
    debug_info = {
        "ocr_response": None,
        "extracted_text": None,
        "link_extraction": None,
        "url_matching": None,
        "solved_check": None,
        "final_status": None,
        "error": None
    }
    
    try:
        # 1. Test OCR API call
        with open(image_path, 'rb') as image_file:
            payload = {
                'apikey': ocr_api_key,
                'OCREngine': '2',
                'scale': 'true',
                'isTable': 'true',
                'detectOrientation': 'true'
            }
            files = {'file': image_file}
            
            response = requests.post(
                'https://api.ocr.space/parse/image',
                files=files,
                data=payload
            )
            debug_info["ocr_response"] = {
                "status_code": response.status_code,
                "response_headers": dict(response.headers)
            }
            
            if not response.ok:
                debug_info["error"] = f"OCR API error: {response.status_code}"
                return debug_info
            
            result = response.json()
            extracted_text = result.get('ParsedResults', [{}])[0].get('ParsedText', '')
            debug_info["extracted_text"] = extracted_text
            
            # 2. Test link extraction
            extracted_link = extract_problem_link(extracted_text)
            debug_info["link_extraction"] = {
                "extracted_link": extracted_link,
                "expected_link": expected_link
            }
            
            # 3. Test URL matching
            if extracted_link:
                normalized_expected = normalize_url(expected_link)
                normalized_extracted = normalize_url(extracted_link)
                debug_info["url_matching"] = {
                    "normalized_expected": normalized_expected,
                    "normalized_extracted": normalized_extracted,
                    "matches": (normalized_extracted in normalized_expected or 
                              normalized_expected in normalized_extracted)
                }
            
            # 4. Test solved status check
            debug_info["solved_check"] = {
                "is_solved": check_problem_solved(extracted_text),
                "text_snippets": re.findall(r'((?:submitted|successful|solved|passed).*?(?:\.|$))', 
                                          extracted_text, 
                                          re.IGNORECASE)
            }
            
            # 5. Final verification status
            debug_info["final_status"] = {
                "verified": (debug_info["url_matching"]["matches"] if debug_info["url_matching"] else False) and 
                           debug_info["solved_check"]["is_solved"]
            }
            
    except Exception as e:
        debug_info["error"] = str(e)
    
    return debug_info

#verify_submission_image = verify_solution_with_ocr
def debug_verification(image_path, expected_link):
    """
    Debug helper function to print detailed verification process
    """
    print(f"\nTesting verification for image: {image_path}")
    print(f"Expected link: {expected_link}")
    print("\n" + "="*50)
    
    try:
        text = pytesseract.image_to_string(Image.open(image_path))
        print("\nExtracted Text:")
        print("-"*50)
        print(text)
        
        is_verified, details = verify_submission_image(image_path, expected_link)
        
        print("\nVerification Results:")
        print("-"*50)
        print(f"Verification passed: {is_verified}")
        print("Details:")
        for key, value in details.items():
            print(f"  {key}: {value}")
        
        return is_verified, details
        
    except Exception as e:
        print(f"Debug error: {str(e)}")
        return False, {'error': str(e)}
# Update the Submission model in the JSON structure
def update_submission_verification(username, problem_title, filename, verification_status, verification_details):
    """Update the submission with verification status"""
    submissions = load_json_file(SUBMISSIONS_FILE)
    
    if username not in submissions:
        submissions[username] = {}
    
    submissions[username][problem_title] = {
        'filename': filename,
        'verified': verification_status,
        'verification_details': verification_details,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    save_json_file(SUBMISSIONS_FILE, submissions)

# Update the submit_solution route

# Update the submit_solution route to ensure consistent data structure
@app.route('/student/submit', methods=['POST'])
@login_required
def student_submit_solution():  # Renamed from submit_solution to avoid conflicts
    try:
        username = session['username']
        problem_title = request.form.get('problem_title')
        
        if 'screenshot' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('student_dashboard'))
            
        file = request.files['screenshot']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('student_dashboard'))
            
        # Get problem details
        problems = load_json_file(PROBLEMS_FILE)
        student_problems = problems.get(username, [])
        problem = next((p for p in student_problems if p['title'] == problem_title), None)
        
        if not problem:
            flash('Problem not found', 'error')
            return redirect(url_for('student_dashboard'))
            
        # Save the file
        filename = secure_filename(f"{username}_{problem_title}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Verify the submission
        is_verified, verification_details = verify_solution_with_ocr(filepath, problem['link'])
        
        # Update submissions
        submissions = load_json_file(SUBMISSIONS_FILE)
        if username not in submissions:
            submissions[username] = {}
            
        submissions[username][problem_title] = {
            'filename': filename,
            'verified': is_verified,
            'verification_details': verification_details,
            'timestamp': datetime.now().isoformat()
        }
        
        save_json_file(SUBMISSIONS_FILE, submissions)
        
        if is_verified:
            flash('Solution verified successfully!', 'success')
        else:
            if 'error' in verification_details:
                flash(f"Verification failed: {verification_details['error']}", 'error')
            else:
                flash('Verification failed. Please ensure your screenshot shows both the problem URL and successful submission.', 'error')
                
        return redirect(url_for('student_dashboard'))
        
    except Exception as e:
        logger.error("Submission error", exc_info=True)
        flash(f"Error processing submission: {str(e)}", 'error')
        return redirect(url_for('student_dashboard'))

# Update the submit_solution route error handling
def handle_verification_error(error_details):
    """Handle verification error details"""
    error_msg = error_details.get('error', 'Unknown error')
    return f"Verification failed: {error_msg}"
 
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Initialize data files on startup
init_data_files()




@app.route('/admin/clear_students', methods=['POST'])
@login_required
@admin_required
def clear_students():
    users = load_json_file(USERS_FILE)
    problems = load_json_file(PROBLEMS_FILE)
    submissions = load_json_file(SUBMISSIONS_FILE)
    
    # Keep only admin users
    users = {username: data for username, data in users.items() if data.get('role') == 'admin'}
    
    # Clear problems and submissions
    problems.clear()
    submissions.clear()
    
    # Save cleared data
    save_json_file(USERS_FILE, users)
    save_json_file(PROBLEMS_FILE, problems)
    save_json_file(SUBMISSIONS_FILE, submissions)
    
    flash('All student data has been cleared.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/student/<username>')
@login_required
@admin_required
def view_student_details(username):
    """
    Display detailed information about a specific student.
    Includes personal info, progress, and submission history.
    """
    # Load necessary data
    users = load_json_file(USERS_FILE)
    problems = load_json_file(PROBLEMS_FILE)
    submissions = load_json_file(SUBMISSIONS_FILE)
    
    # Check if student exists
    student_data = users.get(username)
    if not student_data or student_data.get('role') != 'student':
        flash('Student not found.')
        return redirect(url_for('admin_dashboard'))
    
    # Get student-specific data
    student_problems = problems.get(username, [])
    student_submissions = submissions.get(username, {})
    
    # Format submission data consistently
    formatted_submissions = {}
    for problem_title, submission_data in student_submissions.items():
        if isinstance(submission_data, dict):  # New format
            formatted_submissions[problem_title] = submission_data
        else:  # Legacy format
            formatted_submissions[problem_title] = {
                'filename': submission_data,
                'verified': False,
                'verification_details': {},
                'timestamp': None
            }
    
    return render_template(
        'student_details.html',
        username=username,
        student_data=student_data,
        problems=student_problems,
        submissions=formatted_submissions
    )
'''@app.route('/resubmit_solution', methods=['POST'])
def resubmit_solution():
    if 'screenshot' not in request.files:
        flash("No file uploaded", "error")
        return redirect(url_for('dashboard'))

    file = request.files['screenshot']
    problem_title = request.form.get('problem_title')

    if file.filename == '':
        flash("No file selected", "error")
        return redirect(url_for('dashboard'))

    # Save the file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Update submission record (e.g., mark as 'Pending' again)
    update_submission(problem_title, filename, verified=False)

    flash("Solution resubmitted successfully!", "success")
    return redirect(url_for('dashboard'))


'''
if __name__ == '__main__':
    app.run(debug=True, threaded=True)
