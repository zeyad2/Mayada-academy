
// AOS.init();


        

// Function to check if an element is in viewport
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

// Function to handle scroll animations
// Function to check if an element is in viewport
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

// Function to handle scroll animations
function handleScrollAnimations() {
    const elements = document.querySelectorAll('.team-title, .team-text, .team-btn, .swiper-slide img');
    
    elements.forEach(element => {
        if (isInViewport(element)) {
            element.classList.add('animate'); // Add animate class for animations
        } else {
            element.classList.remove('animate'); // Remove animate class if not in viewport
        }
    });
}

// Event listener for scroll events
window.addEventListener('scroll', () => {
    handleScrollAnimations();
});

// Initial check on page load
handleScrollAnimations();



// signup.html





//signup.html



document.addEventListener("DOMContentLoaded", function () {
    AOS.init();

});



  
//login.html

//login.html end




// ADMIN.html  START

// document.addEventListener('DOMContentLoaded', function() {

//     $('#requestsModal').on('show.bs.modal', function () {
//         $.ajax({
//             url: '/get-requests',
//             type: 'GET',
//             success: function (response) {
//                 var tbody = $('#requestsTableBody');
//                 tbody.empty();
//                 response.forEach(function (request) {
//                     var row = `<tr>
//                         <td>${request.full_name}</td>
//                         <td>${request.user_id}</td>
//                         <td>${request.email}</td>
//                         <td>${request.course_id}</td>
//                         <td class="btn-group">
//                             <button class="btn btn-success accept-request mr-3" data-user-id="${request.user_id}" data-email="${request.EMAIL}" data-course-id="${request.course_id}">Accept</button>
//                             <button class="btn btn-danger delete-request" data-user-id="${request.user_id}" data-email="${request.EMAIL}" data-course-id="${request.course_id}">Delete</button>
//                         </td>
//                     </tr>`;
//                     tbody.append(row);
//                 });
    
//                 $('.accept-request').click(function () {
//                     var userId = $(this).data('user-id');
//                     var email = $(this).data('email');
//                     var courseId = $(this).data('course-id');
                    
//                     $.ajax({
//                         url: '/accept-request',
//                         type: 'POST',
//                         data: JSON.stringify({ userId: userId, email: email, course_id: courseId }),
//                         contentType: 'application/json',
//                         success: function (response) {
//                             alert('Request accepted successfully!');
//                             $('#requestsModal').modal('hide');
//                         },
//                         error: function (xhr, status, error) {
//                             alert('Error accepting request: ' + error);
//                         }
//                     });
//                 });
                
    
//                 $('.delete-request').click(function () {
//                     var userId = $(this).data('user-id');
//                     var courseId = $(this).data('course-id');
                
//                     $.ajax({
//                         url: '/delete-request',
//                         type: 'POST',
//                         data: JSON.stringify({ userId: userId, course_id: courseId }),
//                         contentType: 'application/json',
//                         success: function (response) {
//                             alert('Request deleted successfully!');
//                             $('#requestsModal').modal('hide');
//                             // Optionally, you could also remove the deleted request row from the table here
//                             $(this).closest('tr').remove();
//                         },
//                         error: function (xhr, status, error) {
//                             alert('Error deleting request: ' + error);
//                         }
//                     });
//                 });
                
//             },
//             error: function (xhr, status, error) {
//                 alert('Error fetching requests: ' + error);
//             }
//         });
//     });
    
    
    
//             $('#addCourseForm').submit(function (e) {
//                 e.preventDefault();
//                 var formData = new FormData(this);
    
//                 $.ajax({
//                     url: '/add-course',
//                     type: 'POST',
//                     data: formData,
//                     processData: false,
//                     contentType: false,
//                     success: function (response) {
//                         alert('Course added successfully!');
//                         $('#addCourseModal').modal('hide');
//                     },
//                     error: function (xhr, status, error) {
//                         alert('Error adding course: ' + error);
//                     }
//                 });
//             });
            
    
    
            
//             $('#addLectureForm').submit(function (e) {
//                 e.preventDefault();
//                 var formData = new FormData(this);
            
//                 $.ajax({
//                     url: '/add-lecture',
//                     type: 'POST',
//                     data: formData,
//                     contentType: false,
//                     processData: false,
//                     success: function (response) {
//                         alert('Lecture added successfully!');
//                         $('#addLectureModal').modal('hide');
//                     },
//                     error: function (xhr, status, error) {
//                         alert('Error adding lecture: ' + error);
//                     }
//                 });
//             });
    

    
//     document.getElementById('addPassageBtn').addEventListener('click', function() {
//         const passageContainer = document.createElement('div');
//         passageContainer.classList.add('passage-container');
//         passageContainer.innerHTML = `
//             <div class="form-group">
//                 <label for="passageContent">Passage Content</label>
//                 <textarea class="form-control" name="passageContent[]" required></textarea>
//             </div>
//             <div class="questionsContainer">
//                 <!-- Questions will be added here -->
//             </div>
//             <button type="button" class="btn btn-secondary addQuestionBtn">Add Question</button>
//             <hr/>
//         `;
//         document.getElementById('passagesContainer').appendChild(passageContainer);
    
//         const addQuestionBtn = passageContainer.querySelector('.addQuestionBtn');
//         addQuestionBtn.addEventListener('click', function() {
//             const questionsContainer = passageContainer.querySelector('.questionsContainer');
//             const questionContainer = document.createElement('div');
//             questionContainer.classList.add('question-container');
//             questionContainer.innerHTML = `
//                 <div class="form-group">
//                     <label for="questionText">Question Text</label>
//                     <input type="text" class="form-control" name="questionText[]" required>
//                 </div>
//                 <div class="form-group">
//                     <label>Options</label>
//                     <input type="text" class="form-control mb-3" name="optionA[]" placeholder="Option A" required>
//                     <input type="text" class="form-control mb-3" name="optionB[]" placeholder="Option B" required>
//                     <input type="text" class="form-control mb-3" name="optionC[]" placeholder="Option C" required>
//                     <input type="text" class="form-control mb-3" name="optionD[]" placeholder="Option D" required>
//                 </div>
//                 <div class="form-group">
//                     <label for="correctOption">Correct Option</label>
//                     <select class="form-control" name="correctOption[]" required>
//                         <option value="a">A</option>
//                         <option value="b">B</option>
//                         <option value="c">C</option>
//                         <option value="d">D</option>
//                     </select>
//                 </div>
//                 <hr/>
//             `;
//             questionsContainer.appendChild(questionContainer);
//         });
//     });
//     document.getElementById('addExamForm').addEventListener('submit', function(event) {
//         event.preventDefault();
    
//         const formData = new FormData(this);
     
//         fetch('/add-exam', {
//             method: 'POST',
//             body: formData
//         })
//         .then(response => response.json())
//         .then(data => {
//             if (data.message) {
//                 alert(data.message);
//             } else {
//                 alert('Error adding exam: ' + data.error);
//             }
//         })
//         .catch(error => {
//             console.error('Error:', error);
//             alert('An error occurred: ' + error.message);
//         });
//     });
//     //
     
    
//     document.getElementById('sendEmailsButton').addEventListener('click', function() {
//         if (confirm('Are you sure you want to send reports to all parents?')) {
//           fetch('/send-all-parents-messages', {
//             method: 'POST',
//             headers: {
//               'Content-Type': 'application/json'
//             }
//           })
//           .then(response => response.json())
//           .then(data => {
//             if (data.success) {
//               alert('Emails and WhatsApp messages sent successfully!');
//             } else {
//               alert('Error sending messages: ' + data.error);
//             }
//           })
//           .catch(error => {
//             console.error('Error:', error);
//             alert('An error occurred: ' + error.message);
//           });
//         }
//       });
 
// });






        




        
// ADMIN.HTML END