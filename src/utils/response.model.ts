export const UserResponseExample = {
  message: 'Success',
  data: {
    user: {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin',
      isVerified: true,
      programme: 'Software Engineering',
      dob: '24-10-1998',
      phone: '0123456789',
      address: '2 Pine Street',
      registered: true,
    },
  },
};

export const RegisterResponseExample = {
  message: 'Success',
  data: {
    user: {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin',
      isVerified: true,
      programme: null,
      dob: null,
      phone: null,
      address: null,
      registered: false,
    },
    token: 'block token',
  },
};

export const LoginResponseExample = {
  message: 'Success',
  data: {
    accessToken: 'accessToken',
    refreshToken: 'refreshToken',
    user: {
      email: 'george.asiedu@gmail.com',
      name: 'George Asiedu',
      role: 'Admin',
      isVerified: true,
      programme: null,
      dob: null,
      phone: null,
      address: null,
      registered: false,
    },
  },
};

export const GetAllUsersResponseExample = {
  message: 'Success',
  data: [
    {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin',
      refreshToken: null,
      isVerified: true,
      programme: 'Software Engineering',
      dob: '24-10-1998',
      phone: '0123456789',
      address: '2 Pine Street',
      registered: true,
    },
  ],
};

export const BadRequestExample = [
  'name should not be empty',
  'email must be an email',
  'password must be at least 8 characters long',
];

export const LoginBadRequestExample = [
  'email must be an email',
  'password must be at least 8 characters long',
];
