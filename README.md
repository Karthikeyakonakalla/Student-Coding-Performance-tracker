## Image Album Instructions

To create an image album, you can organize your images in a dedicated folder and reference them in your README file.

1. **Organize Images**: Place all your images in a folder, for example, `images/album`.
2. **Reference Images**: Use the following Markdown syntax to display the images:
   ```markdown
   ![Alt text](images/album/image1.jpg)
   ![Alt text](images/album/image2.jpg)
   ```

### Example
Here’s how you can display images in your README:
```markdown
![Image 1](images/album/image1.jpg)
![Image 2](images/album/image2.jpg)
![Image 3](images/album/image3.jpg)
![Image 4](images/album/image4.jpg)
![Image 5](images/album/image5.jpg)
![Image 6](images/album/image6.jpg)
![Image 7](images/album/image7.jpg)
![Image 8](images/album/image8.jpg)

```

# Project Title: DSAAllocator

## Description
DSAAllocator is a web application designed to allocate Data Structures and Algorithms (DSA) problems to students. Students can solve these problems and submit screenshots of their solutions, which the system will automatically verify.

## Features
### Admin Panel
- **Change Secret PIN**: Update the admin access PIN.
- **Add New Student**: Form to add a new student to the system.
- **Add Users from File**: Upload a file to add multiple users at once.
- **Add New Admin**: Create a new admin account.
- **Delete User**: Remove a user from the system.
- **Current Users**: View and manage the list of all users.
- **File Management**: Upload files and manage directories.

### Student Panel
- **View Total Problems**: Display the total number of problems assigned.
- **View Verified Submissions**: Show the number of verified submissions.
- **Completion Rate**: Display the percentage of problems solved.
- **Problems Table**: List of problems with links to solve them, status of submissions, and actions to submit solutions or view details.

## Installation
To set up the project locally, follow these steps:

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

## Usage
- Access the application in your web browser at `http://localhost:5000`.
- Students can log in, view allocated problems, and submit their solutions.
- Administrators can manage problem allocations and verify submissions.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request.

## Team Garuda
This project is developed by Team Garuda, consisting of the following members:
1. **VBS** - Team Lead
2. **Karthekeya** - Rapid DIV
3. **Raghava** - Debugger
4. **Sandeep** - Design and Testing

## License
This project is licensed under the MIT License.

## Login Details

### Admin Login
- **Username**: admin
- **Password**: admin123
- **Admin Tools Password**: Garuda

### Student Login
- **Username**: [Student ID or Email]
- **Password**: 123

> Note: Replace [Student ID or Email] with the actual student ID or email used for login.

## Admin Tools Features
- **Change Secret PIN**: Update the secret PIN for admin access.
- **Add New Student**: Add a new student to the system.
- **Add Users from File**: Upload a file to add multiple users at once.
- **Add New Admin**: Create a new admin account.
- **Delete User**: Remove a user from the system.
- **Current Users**: View the list of all users in the system.
- **File Management**: Upload files and manage directories.
