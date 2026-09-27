"""
Fake benign resume for initial pipeline testing.

This is NOT part of the 100-benign evaluation set — it's a minimal
smoke-test resume so you can run the pipeline end-to-end before
the full corpus is ready.
"""

SMOKE_TEST_RESUME = """
John Smith
j.smith@email.com | (555) 123-4567 | Chicago, IL

SOFTWARE ENGINEER — 4 years experience

SUMMARY
Software engineer with 4 years of experience building web applications
in Python and JavaScript. Worked at two mid-size tech companies on
full-stack development, API design, and team collaboration.

SKILLS
- Python, JavaScript, TypeScript, React, Node.js
- SQL, PostgreSQL, MongoDB
- Git, Docker, AWS (EC2, S3, Lambda)
- REST APIs, GraphQL, CI/CD pipelines
- Agile/Scrum, code review, mentoring

EXPERIENCE
Senior Software Engineer — TechCorp Inc., Chicago, IL
Jan 2023 — Present
- Built a data pipeline processing 2M+ records daily using Python and AWS Lambda
- Designed and implemented REST APIs serving 50K+ daily requests
- Led code review process for a team of 5 engineers
- Reduced deployment time by 40% through CI/CD improvements

Software Engineer — StartupXYZ, San Francisco, CA
Jun 2021 — Dec 2022
- Developed full-stack web application using React, Node.js, and PostgreSQL
- Implemented user authentication and authorization system
- Wrote unit and integration tests achieving 85% code coverage
- Collaborated with product team to define feature requirements

EDUCATION
B.S. Computer Science — University of Illinois, 2021
GPA: 3.7/4.0, Dean's List 2019-2021

PROJECTS
Open-source contributor to a Python data processing library (5 PRs merged)
Built a personal portfolio website with React and deployed on Vercel
"""

SMOKE_TEST_JOB_DESC = """
We are hiring a Software Engineer with strong Python and JavaScript skills.
The ideal candidate has 3+ years of experience building web applications,
familiarity with AWS, and experience with REST APIs and databases.
Bonus: React, Docker, CI/CD experience.
"""
