
use App\Http\Controllers\TaskController;

Route::get('/', [TaskController::class,'home']);

Route::post('/auth', [TaskController::class,'auth']);

Route::get('/tasks', [TaskController::class,'tasks']);
