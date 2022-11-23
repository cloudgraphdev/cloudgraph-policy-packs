export default {
  id: 'aws-cis-1.5.0-1.3',  
  title: 'AWS CIS 1.3 Ensure security questions are registered in the AWS account',
  
  description: 'The AWS support portal allows account owners to establish security questions that can be used to authenticate individuals calling AWS customer service for support. It is recommended that security questions be established.',
  
  audit: `**From Console:**
  
  1. Login to the AWS account as the 'root' user
  2. On the top right you will see the <Root_Account_Name>
  3. Click on the <Root_Account_Name>
  4. From the drop-down menu Click My Account
  5. In the Configure Security Challenge Questions section on the Personal Information page, configure three security challenge questions.
  6. Click Save questions .`,
  
  rationale: 'When creating a new AWS account, a default super user is automatically created. This account is referred to as the \'root user\' or \'root\' account. It is recommended that the use of this account be limited and highly controlled. During events in which the \'root\' password is no longer accessible or the MFA token associated with \'root\' is lost/destroyed it is possible, through authentication using secret questions and associated answers, to recover \'root\' user login access.',
  
  remediation: `**From Console:**
  
  1. Login to the AWS Account as the 'root' user
  2. Click on the <Root_Account_Name> from the top right of the console
  3. From the drop-down menu Click My Account
  4. Scroll down to the Configure Security Questions section
  5. Click on Edit
  6. Click on each Question
      - From the drop-down select an appropriate question
      - Click on the Answer section
      - Enter an appropriate answer
          - Follow process for all 3 questions
  7. Click Update when complete
  8. Place Questions and Answers and place in a secure physical location`,
  
  references: [],

  severity: 'high',
}
