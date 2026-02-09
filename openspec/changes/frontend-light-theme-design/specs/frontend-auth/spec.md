## ADDED Requirements

### Requirement: Login page SHALL authenticate users via JWT
The frontend SHALL provide a login page at `/login` that accepts username and password, calls `POST /api/v1/auth/login`, and stores the returned JWT token in localStorage.

#### Scenario: Successful login
- **WHEN** user enters valid credentials and clicks "Login"
- **THEN** the frontend SHALL call `POST /api/v1/auth/login`, store the JWT token in localStorage, and redirect to `/dashboard`

#### Scenario: Invalid credentials
- **WHEN** user enters incorrect username or password
- **THEN** the frontend SHALL display an error message "用户名或密码错误" without redirecting

#### Scenario: Empty fields
- **WHEN** user clicks "Login" with empty username or password
- **THEN** the frontend SHALL show inline validation errors and NOT submit the request

### Requirement: Frontend SHALL protect routes with auth guard
The frontend SHALL redirect unauthenticated users to `/login` when accessing any protected route.

#### Scenario: Unauthenticated access to protected route
- **WHEN** a user navigates to `/dashboard` without a valid JWT token in localStorage
- **THEN** the frontend SHALL redirect to `/login`

#### Scenario: Expired token triggers re-login
- **WHEN** an API call returns HTTP 401
- **THEN** the frontend SHALL clear the stored token, redirect to `/login`, and display "登录已过期，请重新登录"

### Requirement: Frontend SHALL provide logout capability
The frontend SHALL provide a logout action in the navigation header.

#### Scenario: User logs out
- **WHEN** user clicks the logout button in the header
- **THEN** the frontend SHALL clear the JWT token from localStorage and redirect to `/login`

### Requirement: Login page SHALL follow Apple Light Theme design
The login page SHALL display a centered card on a `#F5F5F7` background with the oxmon logo, white card with 12px border-radius, and `#0071E3` primary button.

#### Scenario: Login page visual design
- **WHEN** the login page is rendered
- **THEN** the page SHALL display a centered white card (max-width 400px) with Inter/SF Pro font, 12px border-radius, and a blue `#0071E3` "Login" button with 8px border-radius
