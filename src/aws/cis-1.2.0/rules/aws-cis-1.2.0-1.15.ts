/* eslint-disable max-len */
export default {
  id: 'aws-cis-1.2.0-1.15',  
  title: 'AWS CIS 1.15 Ensure security questions are registered in the AWS account',  
  description:
    'The AWS support portal allows account owners to establish security questions that can be used to authenticate individuals calling AWS customer service for support. It is recommended that security questions be established.',  
  audit: `Perform the following in the AWS Management Console:
  
  1. Login to the AWS account as root
  2. On the top right you will see the <_Root_Account_Name_>
  3. Click on the <_Root_Account_Name_>
  4. From the drop-down menu Click My Account
  5. In the Configure Security Challenge Questions section on the Personal
  Information page, configure three security challenge questions.
  6. Click Save questions.`,

  rationale:
    'When creating a new AWS account, a default super user is automatically created. This account is referred to as the "root" account. It is recommended that the use of this account be limited and highly controlled. During events in which the Root password is no longer accessible or the MFA token associated with root is lost/destroyed it is possible, through authentication using secret questions and associated answers, to recover root login access.',

  remediation: `Perform the following in the AWS Management Console:
  
  1. Login to the AWS Account as root
  2. Click on the <_Root_Account_Name_> from the top right of the console
  3. From the drop-down menu Click My Account
  4. Scroll down to the Configure Security Questions section
  5. Click on Edit
  6. Click on each Question  
  
      - From the drop-down select an appropriate question
      - Click on the Answer section
      - Enter an appropriate answer
          - Follow process for all 3 questions  
  
  7. Click Update when complete
  8. Place Questions and Answers and place in a secure physical location
  `,
  references: [],  
  severity: 'medium',
}
