<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Task extends Model
{
    use HasFactory;

    protected $fillable = [
        'title',
        'description',
        'status',
        'task_category_id',
        'user_id',
        'due_date',
    ];

    public function taskCategory()
    {
        return $this->belongsTo(TaskCategory::class);
    }

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}